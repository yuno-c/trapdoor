"""M0 acceptance, evolved: tracing `ls` yields file.open events (JSON schema v1).

M1 changed the stdout contract from raw paths to JSON Lines; the -o flag
separates the event stream from the tracee's own stdout.
"""

import json
import os
import subprocess
from pathlib import Path

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


def find_tracer() -> Path:
    env = os.environ.get("TRAPDOOR_TRACE_BIN")
    if env and Path(env).is_file():
        return Path(env)
    for c in CANDIDATES:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    raise AssertionError(
        "trapdoor-trace binary not found; build first: "
        "cmake -S . -B build && cmake --build build -j"
    )


def find_ls() -> str:
    for cand in ("/run/current-system/sw/bin/ls", "/bin/ls", "/usr/bin/ls"):
        if Path(cand).is_file():
            return cand
    import shutil

    found = shutil.which("ls")
    assert found, "ls not found on PATH"
    return found


def trace_to_json(tracer: Path, events_file: Path, *target: str) -> int:
    """Run target under the tracer; tracee stdout/stderr discarded."""
    proc = subprocess.run(
        [str(tracer), "-o", str(events_file), "--", *target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    return proc.returncode


def load_events(events_file: Path) -> list[dict]:
    evs = []
    for line in events_file.read_text().splitlines():
        if line.strip():
            evs.append(json.loads(line))
    return evs


def test_trace_ls_yields_file_open_events(tmp_path):
    tracer = find_tracer()
    evf = tmp_path / "events.jsonl"
    rc = trace_to_json(tracer, evf, find_ls(), "/tmp")
    assert rc == 0
    evs = load_events(evf)
    assert len(evs) >= 1
    for e in evs:
        assert e["v"] == 1
        assert e["kind"] in KINDS
    opens = [e for e in evs if e["kind"] == "file.open"]
    assert opens, "expected file.open events from ls"
    assert any(o["path"].startswith("/") for o in opens)


def test_cli_run_wraps_tracer(tmp_path):
    tracer = find_tracer()
    env = dict(os.environ, TRAPDOOR_TRACE_BIN=str(tracer))
    env["PYTHONPATH"] = str(ROOT / "src") + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    evf = tmp_path / "events.jsonl"
    proc = subprocess.run(
        ["python3", "-m", "trapdoor.cli", "run", "-o", str(evf),
         "--", find_ls(), "/tmp"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
        env=env,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    evs = load_events(evf)
    assert any(e["kind"] == "file.open" for e in evs)
