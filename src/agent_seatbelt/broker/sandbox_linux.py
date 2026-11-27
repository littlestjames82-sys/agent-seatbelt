"""Linux runtime isolation (spec §6): an unprivileged namespace
launcher. Zero external dependencies — libc calls via ctypes only;
bubblewrap is NOT required.

How it works: the broker spawns this module as a subprocess with a
JSON spec. The launcher creates a user namespace (uid/gid mapped to
the invoking user), then mount/pid (and optionally network)
namespaces, builds a fresh root filesystem out of bind mounts that
contains ONLY what the profile grants, forks — the child is pid 1
in the new pid namespace — applies rlimits, chroots, and execs the
target. Paths not bound into the view do not exist inside it;
symlink/traversal safety comes from the mount view, not string
checks. When pid 1 exits or is killed, the kernel tears the whole
namespace down, detached children included.

Limits: rlimits are the floor (CPU, address space, file size, open
files, process count). A broker-side watchdog additionally counts
the pid namespace's processes and kills the sandbox if the cap is
exceeded (RLIMIT_NPROC alone does not bind a privileged real uid).
cgroup v2 limits are applied only when a writable delegated
subtree exists; run_sandboxed() reports which mechanism actually
applied — never a limit that was not set.
"""

from __future__ import annotations

import ctypes
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 262144

_libc = ctypes.CDLL("libc.so.6", use_errno=True)

# Paths under the user's home that are never visible inside a
# sandbox unless the user explicitly binds them as extended dirs —
# and even then the broker config, not the agent, chose them.
DENIED_HOME_DIRS = (
    ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker",
    ".seatbelt", ".mozilla", ".config/gcloud", ".config/google-chrome",
    ".config/chromium", ".config/BraveSoftware",
    ".local/share/keyrings",
)
DENIED_HOME_FILES = (".netrc",)

_SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64")
_ETC_FILES = ("passwd", "group", "hosts", "nsswitch.conf",
              "resolv.conf", "localtime", "ld.so.cache")
_ETC_DIRS = ("ssl", "alternatives", "ca-certificates")
_DEV_FILES = ("null", "zero", "full", "random", "urandom")


def _err():
    e = ctypes.get_errno()
    return OSError(e, os.strerror(e))


def _unshare(flags):
    if _libc.unshare(flags) != 0:
        raise _err()


def _mount(source, target, fstype, flags, data=None):
    if _libc.mount(
            source.encode() if source else None,
            target.encode(),
            fstype.encode() if fstype else None,
            flags,
            data.encode() if data else None) != 0:
        raise _err()


_SYS_MOUNT_SETATTR = 442
_AT_FDCWD = -100
_MOUNT_ATTR_RDONLY = 0x00000001
_MOUNT_ATTR_NOSUID = 0x00000002


class _MountAttr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64),
                ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64),
                ("userns_fd", ctypes.c_uint64)]


def _set_mount_attrs(target, readonly):
    """Set NOSUID (and RDONLY when asked) on the mount at target.

    Uses mount_setattr(2): the legacy MS_REMOUNT|MS_BIND path is
    refused (EPERM) for binds of directories on filesystems owned
    by the initial user namespace (e.g. overlayfs upper layers),
    while mount_setattr — the API modern util-linux and bwrap use —
    is permitted for mounts in our own namespace. Falls back to the
    legacy remount only when the syscall does not exist; a
    read-only request that cannot be applied fails closed."""
    attr_set = _MOUNT_ATTR_NOSUID
    if readonly:
        attr_set |= _MOUNT_ATTR_RDONLY
    attr = _MountAttr(attr_set, 0, 0, 0)
    r = _libc.syscall(_SYS_MOUNT_SETATTR, _AT_FDCWD,
                      target.encode(), 0, ctypes.byref(attr),
                      ctypes.sizeof(attr))
    if r == 0:
        return
    err = ctypes.get_errno()
    if err != 38:  # ENOSYS: pre-5.12 kernel — legacy path or fail
        raise OSError(err, os.strerror(err))
    flags = MS_BIND | MS_REMOUNT | MS_NOSUID
    if readonly:
        flags |= MS_RDONLY
    _mount(None, target, None, flags, None)


def _bind(source, target, readonly=False, is_file=False):
    if is_file:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        Path(target).touch(exist_ok=True)
    else:
        Path(target).mkdir(parents=True, exist_ok=True)
    _mount(source, target, None, MS_BIND, None)
    _set_mount_attrs(target, readonly)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# Roots the sandbox constructs for itself — an empty private
# /tmp, an empty /proc placeholder, /sys, /dev nodes. Binding the
# host's versions over them would break the view or expose host
# state, so an executable living under one can never be covered
# by a bind.
_UNBINDABLE_ROOTS = ("/tmp", "/proc", "/sys", "/dev")


def _is_covered(path, roots):
    for root in roots:
        root = root.rstrip("/")
        if path == root or path.startswith(root + "/"):
            return True
    return False


def executable_coverage(argv0, cwd, home, workspace, extended_dirs):
    """Decide how the request's executable will exist inside the
    sandbox view. Returns (exec_root, problem):

    - (None, None): already covered by the planned binds, or a
      bare name the in-sandbox PATH search resolves under covered
      roots (every directory on the sandbox PATH is under /usr or
      /bin).
    - (root, None): not covered — bind `root` (the executable's
      top-level path component) read-only to cover it. This is
      what makes interpreters installed outside the default
      system view work: /opt/hostedtoolcache on hosted CI
      runners, /srv, a vendored toolchain root.
    - (None, problem): cannot be covered — the execution must
      fail closed with `problem` as the recorded reason. The
      user's home is never bound into the view (an empty shadow
      stands at its path), and the sandbox's own /tmp, /proc,
      /sys and /dev are constructed, not bound, so executables
      under those roots are uncoverable by design.
    """
    if "/" not in argv0:
        return None, None
    if os.path.isabs(argv0):
        resolved = os.path.realpath(argv0)
    else:
        resolved = os.path.realpath(os.path.join(cwd, argv0))
    covered = list(_SYSTEM_DIRS) + [workspace] + [
        (e["path"] if isinstance(e, dict) else e)
        for e in extended_dirs]
    if _is_covered(resolved, covered):
        return None, None
    if not os.path.exists(resolved):
        return None, ("executable %s does not exist on the host "
                      "and is not covered by the sandbox view"
                      % argv0)
    parts = [p for p in resolved.split("/") if p]
    if len(parts) < 2:
        return None, ("executable %s cannot be covered by the "
                      "sandbox view" % argv0)
    root = "/" + parts[0]
    home_parts = [p for p in home.split("/") if p]
    home_root = "/" + home_parts[0] if home_parts else None
    if root in _UNBINDABLE_ROOTS or root == home_root:
        return None, ("executable %s lives under %s, which is "
                      "never bound into the sandbox view (the "
                      "user's home is shadowed, never bound, and "
                      "the sandbox constructs its own /tmp, /proc, "
                      "/sys and /dev)" % (argv0, root))
    return root, None


def _setup_userns():
    euid, egid = os.geteuid(), os.getegid()
    _unshare(CLONE_NEWUSER)
    try:
        _write("/proc/self/setgroups", "deny")
    except OSError:
        pass
    _write("/proc/self/gid_map", "0 %d 1" % egid)
    _write("/proc/self/uid_map", "0 %d 1" % euid)


def _build_root(spec, newroot):
    """Assemble the sandbox root under newroot (host paths still
    visible — this runs before chroot, inside our mount ns)."""
    home = spec["home"]
    workspace = spec["workspace"]
    profile = spec["profile"]
    os.makedirs(newroot, exist_ok=True)
    _mount("tmpfs", newroot, "tmpfs", 0, "mode=0755")
    root = Path(newroot)

    for sysdir in _SYSTEM_DIRS:
        if Path(sysdir).is_dir():
            _bind(sysdir, str(root / sysdir.lstrip("/")), readonly=True)
    # The executable's own root, when executable_coverage() found
    # it outside the default view (e.g. /opt, /srv): bound
    # read-only at its own path so the target exists inside. A
    # kernel refusal here (some container runtimes refuse binds
    # of particular roots) propagates as a setup failure — the
    # execution fails closed with the reason recorded, never an
    # opaque exit code.
    exec_root = spec.get("exec_root")
    if exec_root:
        try:
            _bind(exec_root, str(root / exec_root.lstrip("/")),
                  readonly=True)
        except OSError as exc:
            raise OSError(
                "could not bind executable root %s into the "
                "sandbox view: %s" % (exec_root, exc)) from exc
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    for name in _ETC_FILES:
        src = Path("/etc") / name
        if name == "resolv.conf" and spec["network"] == "none":
            continue  # no resolver config in a no-network sandbox
        if src.is_file():
            _bind(str(src), str(etc / name), readonly=True, is_file=True)
    for name in _ETC_DIRS:
        src = Path("/etc") / name
        if src.is_dir():
            _bind(str(src), str(etc / name), readonly=True)
    dev = root / "dev"
    dev.mkdir(parents=True, exist_ok=True)
    for name in _DEV_FILES:
        src = Path("/dev") / name
        if src.exists():
            _bind(str(src), str(dev / name), is_file=True)
    (dev / "pts").mkdir(exist_ok=True)
    (dev / "shm").mkdir(exist_ok=True)
    _mount("tmpfs", str(dev / "shm"), "tmpfs", 0, "mode=1777")
    (root / "proc").mkdir(exist_ok=True)
    (root / "sys").mkdir(exist_ok=True)
    # /tmp and the home shadow are plain directories on the private
    # root tmpfs: still empty and unreachable from the host, and
    # keeping them mount-free means binds of granted paths beneath
    # them (a workspace under /tmp or $HOME) can still be remounted
    # read-only — a bind remount stacked over our own tmpfs is
    # refused by the kernel.
    tmp_dir = root / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    os.chmod(tmp_dir, 0o1777)

    # The user's real home is never bound. An empty directory
    # stands at the home path so $HOME resolves to a directory
    # that contains nothing of the user's.
    home_target = root / home.lstrip("/")
    home_target.mkdir(parents=True, exist_ok=True)

    def _visible_bind(source, readonly=False):
        target = root / source.lstrip("/")
        _bind(source, str(target), readonly=readonly)
        return target

    # Workspace at its own absolute path, so paths are identical
    # inside and outside.
    ws_readonly = profile == "read-only"
    _visible_bind(workspace, readonly=ws_readonly)
    for entry in spec.get("extended_dirs", []):
        path = entry["path"] if isinstance(entry, dict) else entry
        mode = entry.get("mode", "rw") if isinstance(entry, dict) else "rw"
        if Path(path).is_dir():
            _visible_bind(path, readonly=(mode == "ro"))

    # Mask the always-denied locations wherever a bound tree would
    # otherwise expose them (e.g. the workspace IS the home dir, or
    # an extended dir is an ancestor of ~/.ssh): an empty tmpfs over
    # the path makes the real contents unreachable.
    bound_trees = [workspace] + [
        (e["path"] if isinstance(e, dict) else e)
        for e in spec.get("extended_dirs", [])]
    for rel in DENIED_HOME_DIRS:
        denied = str(Path(home) / rel)
        for tree in bound_trees:
            if denied == tree or denied.startswith(tree.rstrip("/") + "/"):
                target = root / denied.lstrip("/")
                target.mkdir(parents=True, exist_ok=True)
                _mount("tmpfs", str(target), "tmpfs", MS_NOSUID,
                       "mode=0700")
                break
    for rel in DENIED_HOME_FILES:
        denied = Path(home) / rel
        for tree in bound_trees:
            if str(denied).startswith(tree.rstrip("/") + "/"):
                target = root / str(denied).lstrip("/")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch(exist_ok=True)
                _mount("/dev/null", str(target), None, MS_BIND, None)
                break


def _count_uid_processes(uid):
    count = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/status" % pid, encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    if line.startswith("Uid:"):
                        if int(line.split()[1]) == uid:
                            count += 1
                        break
        except OSError:
            continue
    return count


def _apply_rlimits(limits, nproc_baseline=0):
    cpu = int(limits.get("cpu_seconds", 120))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
    mem = int(limits.get("address_space_mb", 2048)) * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    fsize = int(limits.get("file_size_mb", 256)) * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    nofile = int(limits.get("open_files", 1024))
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,
                       (min(nofile, hard), hard))
    # RLIMIT_NPROC is counted per real uid across the host, so the
    # cap is baseline + allowance (the watchdog enforces the same
    # allowance from outside regardless of uid privilege). The
    # baseline is counted by the launcher on the host side, before
    # the chroot hides /proc.
    nproc = nproc_baseline + int(limits.get("processes", 128))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    except (ValueError, OSError):
        pass


def _write_error_file(status_path, stage, message):
    """Record a sandbox setup/exec failure next to the status
    file, where run_sandboxed() reads it and the broker turns it
    into a FAILED execution with the reason attached. Best
    effort: the launcher's stderr and exit code remain as the
    fallback signal."""
    try:
        _write(status_path + ".error", json.dumps(
            {"stage": stage, "error": message}))
    except OSError:
        pass


def _launcher_main(spec_path, status_path):
    with open(spec_path, encoding="utf-8") as fh:
        spec = json.load(fh)
    newroot = tempfile.mkdtemp(prefix="seatbelt-root-")
    try:
        _setup_userns()
        flags = CLONE_NEWNS | CLONE_NEWPID
        if spec["network"] == "none":
            flags |= CLONE_NEWNET
        _unshare(flags)
        _mount(None, "/", None, MS_REC | MS_PRIVATE, None)
        _build_root(spec, newroot)
        nproc_baseline = _count_uid_processes(os.getuid())

        # Exec-error pipe: the write end is CLOEXEC, so a
        # successful exec closes it silently; if anything in the
        # child fails before or during exec, the child writes the
        # concrete error here first. This is how the broker tells
        # "the sandbox could not run this" apart from a target
        # that simply exited 127 — the failure gets a reason, not
        # a bare exit code with empty output.
        err_r, err_w = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            # pid 1 in the new pid namespace.
            os.close(err_r)
            try:
                proc_mode = "fresh"
                try:
                    _mount("proc", str(Path(newroot) / "proc"), "proc",
                           MS_NOSUID, None)
                except OSError:
                    # Container runtimes that mask paths in the
                    # parent /proc make ANY new proc mount (and any
                    # bind of /proc) EPERM/EINVAL in a userns. The
                    # sandbox then ships an empty /proc directory:
                    # tools that enumerate processes see nothing,
                    # which fails safe. The mode is reported in the
                    # status file and recorded in the ledger.
                    proc_mode = "none"
                if status_path:
                    _write(status_path + ".child", json.dumps(
                        {"proc_mode": proc_mode}))
                os.chroot(newroot)
                os.chdir("/")
                _apply_rlimits(spec["limits"], nproc_baseline)
                os.setsid()
                os.chdir(spec["cwd"])
                env = {
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                            "/usr/bin:/sbin:/bin",
                    "HOME": spec["home"],
                    "TMPDIR": "/tmp",
                    "LANG": "C.UTF-8",
                    "TERM": "dumb",
                }
                os.execvpe(spec["argv"][0], spec["argv"], env)
            except BaseException as exc:
                try:
                    os.write(err_w, ("%s: %s" % (
                        type(exc).__name__, exc)).encode(
                            "utf-8", "replace")[:4096])
                except OSError:
                    pass
                os._exit(127)
        os.close(err_w)
        # Launcher (parent): report the namespace init's host pid,
        # then wait and propagate its status.
        if status_path:
            _write(status_path, json.dumps(
                {"init_pid": child, "newroot": newroot}))
        _pid, status = os.waitpid(child, 0)
        exec_error = b""
        try:
            while True:
                chunk = os.read(err_r, 4096)
                if not chunk:
                    break
                exec_error += chunk
        except OSError:
            pass
        os.close(err_r)
        if exec_error and status_path:
            _write_error_file(
                status_path, "exec",
                "sandbox could not execute %s: %s" % (
                    spec["argv"][0],
                    exec_error.decode("utf-8", "replace")))
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return 128 + os.WTERMSIG(status)
        return 1
    finally:
        # The mount namespace dies with this process; the tmpfs
        # root vanishes with it. Best-effort dir cleanup only.
        try:
            os.rmdir(newroot)
        except OSError:
            pass


_probe_cache = None


def probe():
    """Can this environment actually run a sandboxed execution?

    Honest probing: a bare unshare(CLONE_NEWUSER) succeeding is
    NOT evidence the launcher works — hosted CI runners restrict
    later steps (mounts, exec inside the view) while leaving
    unshare itself permitted, which used to surface only as
    opaque per-execution failures. So the probe exercises the
    real launcher path end to end: it runs /bin/true through
    run_sandboxed() and requires a clean exit. The result is
    cached for the life of the process — broker startup and the
    test suite's skip checks each pay for one real sandbox run,
    not one per call."""
    global _probe_cache
    if _probe_cache is not None:
        return _probe_cache
    _probe_cache = _probe_real()
    return _probe_cache


def _probe_real():
    code = (
        "import ctypes,sys;"
        "libc=ctypes.CDLL('libc.so.6',use_errno=True);"
        "r=libc.unshare(0x10000000);"
        "sys.exit(0 if r==0 else 1)")
    try:
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, timeout=15)
        if proc.returncode != 0:
            return False
    except Exception:
        return False
    tmp = tempfile.mkdtemp(prefix="seatbelt-probe-")
    ws = os.path.join(tmp, "ws")
    os.mkdir(ws)
    try:
        spec = {
            "sandbox_id": "probe",
            "argv": ["/bin/true"],
            "cwd": ws,
            "workspace": ws,
            "profile": "read-only",
            "extended_dirs": [],
            "network": "none",
            "home": os.path.join(tmp, "home"),
            "limits": {"cpu_seconds": 15, "address_space_mb": 512,
                       "memory_mb": 512, "file_size_mb": 16,
                       "open_files": 256, "processes": 32},
            "timeout_seconds": 15,
        }
        outcome = run_sandboxed(spec, 65536)
        return outcome.get("error") is None and \
            outcome.get("exit_code") == 0
    except Exception:
        return False
    finally:
        for path in (ws, tmp):
            try:
                os.rmdir(path)
            except OSError:
                pass


def _ns_process_count(init_pid):
    """How many processes live in init_pid's pid namespace."""
    try:
        ns = os.readlink("/proc/%d/ns/pid" % init_pid)
    except OSError:
        return 0
    count = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            if os.readlink("/proc/%s/ns/pid" % pid) == ns:
                count += 1
        except OSError:
            continue
    return count


def _try_cgroup(sandbox_id, init_pid, limits):
    """Apply cgroup v2 limits if a writable delegated subtree
    exists. Returns the cgroup path or None (rlimits then rule)."""
    base = os.environ.get("SEATBELT_CGROUP_DIR")
    candidates = [base] if base else ["/sys/fs/cgroup"]
    for cand in candidates:
        if not cand:
            continue
        path = Path(cand) / ("seatbelt-" + sandbox_id)
        try:
            path.mkdir()
        except OSError:
            continue
        try:
            mem = int(limits.get("memory_mb",
                                 limits.get("address_space_mb", 2048)))
            (path / "memory.max").write_text(
                str(mem * 1024 * 1024), encoding="utf-8")
            (path / "pids.max").write_text(
                str(int(limits.get("processes", 128))),
                encoding="utf-8")
            (path / "cgroup.procs").write_text(
                str(init_pid), encoding="utf-8")
            return str(path)
        except OSError:
            try:
                path.rmdir()
            except OSError:
                pass
            continue
    return None


class _TailBuffer:
    def __init__(self, cap):
        self.cap = cap
        self.data = bytearray()
        self.truncated = False

    def feed(self, chunk):
        self.data.extend(chunk)
        if len(self.data) > self.cap:
            del self.data[: len(self.data) - self.cap]
            self.truncated = True


def run_sandboxed(spec, output_cap, on_spawn=None):
    """Run one sandboxed execution. Called by the broker; blocks
    until exit/timeout/limit-kill. on_spawn, if given, is called as
    on_spawn(sandbox_id, launcher_pid, init_pid) once both pids
    are known, so the broker can record them in its run manifest
    for crash recovery. Returns a result dict:
    {exit_code, timed_out, limit_exceeded, mechanism, init_pid,
     sandbox_id, stdout, stderr, truncated, error, exec_root}.
    `error` is None on every path where the target actually ran;
    a sandbox setup or exec failure sets it to the concrete
    reason (and exit_code may then be None), so callers can fail
    the execution closed instead of reporting an opaque code.
    `exec_root` records the extra read-only root bind added to
    cover the executable, when one was needed."""
    import threading

    sandbox_id = spec["sandbox_id"]
    spec_path = status_path = None
    proc = None
    # Executable coverage is decided before anything is spawned:
    # an uncoverable target fails closed right here with the
    # reason in the outcome, and a coverable one gets its root
    # added to the spec so the launcher binds it into the view.
    exec_root, problem = executable_coverage(
        spec["argv"][0], spec["cwd"], spec["home"],
        spec["workspace"], spec.get("extended_dirs", []))
    if problem is not None:
        return {
            "exit_code": None,
            "timed_out": False,
            "limit_exceeded": None,
            "mechanism": "none (sandbox setup failed)",
            "proc_mode": None,
            "init_pid": None,
            "sandbox_id": sandbox_id,
            "stdout": b"",
            "stderr": b"",
            "truncated": False,
            "error": problem,
            "exec_root": None,
        }
    if exec_root:
        spec = dict(spec, exec_root=exec_root)
    try:
        fd, spec_path = tempfile.mkstemp(prefix="seatbelt-spec-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(spec, fh)
        fd, status_path = tempfile.mkstemp(prefix="seatbelt-status-")
        os.close(fd)
        os.unlink(status_path)  # launcher creates it when ready
        # The launcher is a fresh interpreter: make this package
        # importable in it even when the broker itself is running
        # from a source tree rather than an installed wheel.
        env = dict(os.environ)
        pkg_parent = str(Path(__file__).resolve().parents[2])
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = pkg_parent + (
            os.pathsep + existing if existing else "")
        proc = subprocess.Popen(
            [sys.executable, "-m", "agent_seatbelt.broker.sandbox_linux",
             "--spec-file", spec_path, "--status-file", status_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, env=env)
        out_buf, err_buf = _TailBuffer(output_cap), _TailBuffer(output_cap)

        def _drain(stream, buf):
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                buf.feed(chunk)

        threads = [
            threading.Thread(target=_drain, args=(proc.stdout, out_buf),
                             daemon=True),
            threading.Thread(target=_drain, args=(proc.stderr, err_buf),
                             daemon=True),
        ]
        for t in threads:
            t.start()

        init_pid = None
        deadline = time.monotonic() + float(spec["timeout_seconds"])
        timed_out = False
        limit_exceeded = None
        cgroup_path = None
        max_processes = int(spec["limits"].get("processes", 128))
        while True:
            if init_pid is None and os.path.exists(status_path):
                try:
                    with open(status_path, encoding="utf-8") as fh:
                        init_pid = json.load(fh)["init_pid"]
                    cgroup_path = _try_cgroup(sandbox_id, init_pid,
                                              spec["limits"])
                    if on_spawn is not None:
                        on_spawn(sandbox_id, proc.pid, init_pid)
                except (OSError, ValueError, KeyError):
                    init_pid = None
            if proc.poll() is not None:
                break
            now = time.monotonic()
            if now > deadline:
                timed_out = True
                _kill_tree(proc, init_pid)
                break
            if init_pid is not None and \
                    _ns_process_count(init_pid) > max_processes + 2:
                limit_exceeded = "processes"
                _kill_tree(proc, init_pid)
                break
            time.sleep(0.05)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_tree(proc, init_pid)
            proc.wait(timeout=10)
        for t in threads:
            t.join(timeout=5)
        if cgroup_path:
            try:
                Path(cgroup_path).rmdir()
            except OSError:
                pass
        proc_mode = None
        error = None
        if status_path:
            try:
                with open(status_path + ".child", encoding="utf-8") as fh:
                    proc_mode = json.load(fh).get("proc_mode")
            except (OSError, ValueError):
                pass
            try:
                with open(status_path + ".error",
                          encoding="utf-8") as fh:
                    error = json.load(fh).get("error")
            except (OSError, ValueError):
                pass
        return {
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "limit_exceeded": limit_exceeded,
            "mechanism": "cgroup-v2" if cgroup_path else
                         "rlimit+watchdog",
            "proc_mode": proc_mode,
            "init_pid": init_pid,
            "sandbox_id": sandbox_id,
            "stdout": bytes(out_buf.data),
            "stderr": bytes(err_buf.data),
            "truncated": out_buf.truncated or err_buf.truncated,
            "error": error,
            "exec_root": exec_root,
        }
    finally:
        for p in (spec_path, status_path,
                  (status_path + ".child") if status_path else None,
                  (status_path + ".error") if status_path else None):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass


def _kill_tree(proc, init_pid):
    """Kill the launcher's process group AND the namespace init.
    Killing init collapses the pid namespace, which takes every
    detached/double-forked child with it."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    if init_pid:
        for target in (init_pid,):
            try:
                os.killpg(target, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    os.kill(target, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass


def gc_orphans(manifest_dir, current_run_id):
    """Startup sweep (spec §6.4): for every prior run's manifest,
    kill any recorded sandbox init/pgid that is still alive and
    drop the manifest. Returns the number of orphans reaped."""
    reaped = 0
    mdir = Path(manifest_dir)
    if not mdir.is_dir():
        return 0
    for entry in sorted(mdir.glob("*.json")):
        if entry.stem == current_run_id:
            continue
        try:
            doc = json.loads(entry.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for sb in doc.get("sandboxes", []):
            alive = False
            for key in ("init_pid", "launcher_pid"):
                pid = sb.get(key)
                if pid:
                    try:
                        os.kill(pid, 0)
                        alive = True
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                    if alive:
                        for killer in (os.killpg, os.kill):
                            try:
                                killer(pid, signal.SIGKILL)
                            except (ProcessLookupError, PermissionError,
                                    OSError):
                                pass
            if alive:
                reaped += 1
        try:
            entry.unlink()
        except OSError:
            pass
    return reaped


def _main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--probe"]:
        return 0 if probe() else 1
    spec_path = status_path = None
    i = 0
    while i < len(argv):
        if argv[i] == "--spec-file" and i + 1 < len(argv):
            spec_path = argv[i + 1]
            i += 2
        elif argv[i] == "--status-file" and i + 1 < len(argv):
            status_path = argv[i + 1]
            i += 2
        else:
            i += 1
    if not spec_path:
        sys.stderr.write("usage: sandbox_linux --spec-file F "
                         "[--status-file F] | --probe\n")
        return 2
    try:
        return _launcher_main(spec_path, status_path)
    except OSError as exc:
        sys.stderr.write("sandbox launcher failed: %s\n" % exc)
        if status_path:
            _write_error_file(status_path, "setup",
                              "sandbox setup failed: %s" % exc)
        return 126


if __name__ == "__main__":
    sys.exit(_main())
