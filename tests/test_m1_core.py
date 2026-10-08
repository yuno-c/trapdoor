"""M1 acceptance: seccomp+ptrace core, multiprocess follow, JSON event stream.

Acceptance (brief): tracing `npm install` of a small package produces a
complete, correctly attributed event stream with no hangs and no orphaned
processes. Network egress in this sandbox is unavailable, so the npm test
installs a local fixture package offline (still multi-process: npm -> sh
-> node postinstall).
"""

import json
import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [
    ROOT / "build" / "tracer" / "trapdoor-trace",
    ROOT / "build" / "trapdoor-trace",
]
KINDS = {
    "file.open",
    "file.write",
    "file.delete",
    "file.rename",
    "net.connect",
    "net.bind",
    "proc.exec",
    "proc.exit",
}

NPM = shutil.which("npm")


def find_tracer() -> Path:
    env = os.environ.get("TRAPDOOR_TRACE_BIN")
    if env and Path(env).is_file():
        return Path(env)
    for c in CANDIDATES:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    raise AssertionError("trapdoor-trace not built (cmake -S . -B build ...)")


def trace(tmp_path: Path, *target: str, timeout: int = 60):
    """Run target under tracer; return (returncode, events)."""
    tracer = find_tracer()
    evf = tmp_path / "events.jsonl"
    if evf.exists():
        evf.unlink()
    proc = subprocess.run(
        [str(tracer), "-o", str(evf), "--", *target],
        stdout=subprocess.DEVNULL,  # tracee output must not touch the stream
        stderr=subprocess.DEVNULL,
        timeout=timeout,
    )
    evs = [json.loads(l) for l in evf.read_text().splitlines() if l.strip()]
    return proc.returncode, evs


def test_schema_and_required_fields(tmp_path):
    rc, evs = trace(tmp_path, "sh", "-c", "echo hi >/dev/null")
    assert rc == 0
    assert evs, "expected events"
    prev_t = -1.0
    for e in evs:
        assert e["v"] == 1
        assert isinstance(e["t"], (int, float)) and e["t"] >= 0
        assert e["t"] >= prev_t  # single tracer clock: non-decreasing
        prev_t = e["t"]
        assert isinstance(e["pid"], int) and isinstance(e["ppid"], int)
        assert e["exe"], "exe must never be empty"
        assert e["kind"] in KINDS


def test_multiprocess_attribution(tmp_path):
    victim = tmp_path / "secret.txt"
    victim.write_text("data")
    parent = tmp_path / "parent.sh"
    parent.write_text(f'#!/bin/sh\ncat "{victim}" >/dev/null\n')
    parent.chmod(0o755)

    rc, evs = trace(tmp_path, str(parent))
    assert rc == 0
    execs = [e for e in evs if e["kind"] == "proc.exec"]
    assert any("cat" in (e["argv"] + [e["path"]])[0]
               or any("cat" in a for a in e["argv"]) for e in execs), execs
    cat_exec = next(e for e in execs if any("cat" in a for a in e["argv"]))
    root_pids = {e["pid"] for e in evs if e["ppid"] == 0}
    assert cat_exec["pid"] not in root_pids, "cat must be a child, not root"
    assert cat_exec["ppid"] in {e["pid"] for e in evs}, "ppid must link"
    opens = [e for e in evs
             if e["kind"] == "file.open" and e["path"] == str(victim)]
    assert opens, "expected the child to open the fixture file"
    assert any(o["pid"] == cat_exec["pid"] for o in opens), (
        "file.open must be attributed to the cat child, not the parent")


def test_exit_code_passthrough_and_attributed_exit(tmp_path):
    rc, evs = trace(tmp_path, "sh", "-c", "exit 7")
    assert rc == 7, "tracer must propagate the root exit code"
    exits = [e for e in evs if e["kind"] == "proc.exit" and e["code"] == 7]
    assert exits and all(e["exe"] for e in exits)


def test_signal_death_reported_distinctly(tmp_path):
    rc, evs = trace(tmp_path, "sh", "-c", "kill -9 $$")
    assert rc == 128 + 9
    exits = [e for e in evs if e.get("signal") == 9]
    assert exits, "expected a proc.exit with signal 9"


def test_relative_paths_resolved(tmp_path):
    """chdir-relative and dirfd-relative opens must resolve to absolute.

    A secret-access rule matching `~/.ssh/*` only works if the event
    carries the resolved path, not the raw `id_rsa` the tracee passed.
    """
    work = tmp_path / "work"
    work.mkdir()
    (work / "rel.txt").write_text("x")
    ssh = tmp_path / "home" / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "id_rsa").write_text("fake")
    d = tmp_path / "d"
    d.mkdir()
    (d / "inner.txt").write_text("y")

    client = (
        f"import os; os.chdir('{work}'); open('rel.txt').read();"
        f"dfd=os.open('{d}', os.O_RDONLY|os.O_DIRECTORY);"
        " os.open('inner.txt', os.O_RDONLY, dir_fd=dfd);"
        f"os.chdir('{ssh}'); open('id_rsa').read()"
    )
    rc, evs = trace(tmp_path, "python3", "-c", client)
    assert rc == 0
    paths = [e["path"] for e in evs if e["kind"] == "file.open"]
    assert str(work / "rel.txt") in paths, paths
    assert str(d / "inner.txt") in paths, paths
    assert str(ssh / "id_rsa") in paths, paths
    assert not any(p == "id_rsa" or p == "rel.txt" for p in paths), (
        "unresolved relative path leaked into the stream")


def test_symlink_alias_resolves_to_target(tmp_path):
    """ln -s ~/.ssh ~/innocent must not hide the real target from rules."""
    import os.path

    real = tmp_path / "real-ssh"
    real.mkdir()
    (real / "id_rsa").write_text("fake")
    (tmp_path / "innocent").symlink_to(real, target_is_directory=True)
    (tmp_path / "notes.txt").symlink_to(real / "id_rsa")

    client = (f"import os; os.chdir('{tmp_path}');"
              " open('innocent/id_rsa').read(); open('notes.txt').read()")
    rc, evs = trace(tmp_path, "python3", "-c", client)
    assert rc == 0
    paths = [e["path"] for e in evs if e["kind"] == "file.open"]
    want = os.path.realpath(str(real / "id_rsa"))
    hits = [p for p in paths if p == want]
    assert len(hits) == 2, paths
    assert not any("innocent" in p or "notes.txt" in p for p in paths), (
        "symlink alias leaked into the stream: " + str(paths))


def test_net_connect_localhost(tmp_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            c.recv(64)
            c.close()
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    rc, evs = trace(
        tmp_path, "python3", "-c",
        f"import socket; s=socket.create_connection(('127.0.0.1',{port}));"
        " s.sendall(b'hi'); s.close()")
    assert rc == 0
    conns = [e for e in evs if e["kind"] == "net.connect"]
    assert any(c["addr"] == "127.0.0.1" and c["port"] == port
               for c in conns), conns


@pytest.mark.skipif(NPM is None, reason="npm not on PATH")
def test_npm_install_offline_fixture(tmp_path):
    """M1 acceptance: full attributed stream for an npm install (offline)."""
    pkgdir = tmp_path / "evil-1.0.0"
    pkgdir.mkdir()
    (pkgdir / "package.json").write_text(
        '{"name":"evil","version":"1.0.0","scripts":{"postinstall":'
        '"node -e \\"require(\'fs\').writeFileSync(\'marker.txt\',\'x\')\\""}}')
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text('{"name":"proj","version":"0.0.0"}')

    env = dict(os.environ,
               HOME=str(tmp_path / "home"),
               npm_config_cache=str(tmp_path / "npmcache"),
               npm_config_update_notifier="false")
    (tmp_path / "home").mkdir()

    tracer = find_tracer()
    evf = tmp_path / "events.jsonl"
    proc = subprocess.run(
        [str(tracer), "-o", str(evf), "--", NPM, "install", str(pkgdir),
         "--no-save", "--no-audit", "--no-fund", "--loglevel=error"],
        cwd=str(proj),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=180,
        env=env,
    )
    assert proc.returncode == 0, "fixture install must succeed"
    evs = [json.loads(l) for l in evf.read_text().splitlines() if l.strip()]
    assert len(evs) > 100, f"expected a full stream, got {len(evs)}"

    pids = {e["pid"] for e in evs}
    assert len(pids) >= 2, "npm must spawn children (multi-process)"
    # Every non-root pid links to a known pid (attribution integrity).
    for e in evs:
        if e["ppid"] != 0:
            assert e["ppid"] in pids, f"orphan ppid edge: {e}"
    # Every traced pid reports its exit (no hangs, no lost processes).
    exited = {e["pid"] for e in evs if e["kind"] == "proc.exit"}
    assert exited == pids, f"missing proc.exit: {pids - exited}"

    # The postinstall payload: a node process writes marker.txt.
    writes = [e for e in evs
              if e["kind"] in ("file.open", "file.write")
              and e.get("path", "").endswith("marker.txt")]
    assert writes, "postinstall file write not observed"
    assert any("node" in w["exe"] for w in writes), (
        "marker write must be attributed to node, got: "
        + str([w["exe"] for w in writes]))
    assert any(e["kind"] == "proc.exec" for e in evs)
