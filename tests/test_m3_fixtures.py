"""M3: Simulated-attacker fixture tests.

Proves that harmless simulated-attacker fixtures trigger *exactly* their
expected rules (strict set equality, not mere subset/containment).
Every fixture strictly refuses to run unless inside an authenticated fake HOME.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import pytest
from trapdoor.events import load_events
from trapdoor.rules import evaluate, load_rules

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
CANDIDATES = [
    ROOT / "build" / "tracer" / "trapdoor-trace",
    ROOT / "build" / "trapdoor-trace",
]


def find_tracer() -> Path:
    env = os.environ.get("TRAPDOOR_TRACE_BIN")
    if env and Path(env).is_file():
        return Path(env)
    for c in CANDIDATES:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    raise AssertionError("trapdoor-trace binary not found")


def run_fixture(
    fixture_name: str,
    tmp_path: Path,
    fake_home: Path,
    project_dir: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[set[str], list]:
    """Execute a fixture under the tracer and evaluate rule hits.

    Ensures the fake home safety marker exists before execution.
    Returns (set_of_rule_ids, raw_hits_list).
    """
    fake_home.mkdir(parents=True, exist_ok=True)
    marker = fake_home / ".trapdoor-fake-home"
    if not marker.is_file():
        marker.write_text("trapdoor-fake-home-active\n")

    if project_dir is None:
        project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)

    events_path = tmp_path / f"{fixture_name}.events.jsonl"
    fixture_script = FIXTURES_DIR / fixture_name
    assert fixture_script.is_file(), f"Fixture script not found: {fixture_script}"

    env = dict(
        os.environ,
        HOME=str(fake_home),
        PYTHONPATH=str(ROOT / "src"),
        TRAPDOOR_TRACE_BIN=str(find_tracer()),
    )
    if extra_env:
        env.update(extra_env)

    tracer = find_tracer()
    proc = subprocess.run(
        [str(tracer), "-o", str(events_path), "--", sys.executable, str(fixture_script)],
        cwd=str(project_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"Fixture process failed (exit {proc.returncode}):\n{proc.stderr}"

    events = load_events(events_path)
    rules = load_rules()
    hits = evaluate(events, rules, project=str(project_dir), home=str(fake_home))

    rule_ids = {h.rule_id for h in hits}
    return rule_ids, hits


@pytest.mark.parametrize(
    "fixture_name",
    [
        "credential_theft.py",
        "beacon.py",
        "fetch_and_execute.py",
        "persistence.py",
        "clean_control.py",
    ],
)
def test_fixtures_refuse_to_run_without_fake_home_marker(tmp_path, fixture_name):
    """Every fixture must abort immediately if $HOME/.trapdoor-fake-home is absent."""
    unmarked_home = tmp_path / "unmarked_home"
    unmarked_home.mkdir(parents=True)
    # Explicitly ensure marker is absent
    assert not (unmarked_home / ".trapdoor-fake-home").exists()

    fixture_script = FIXTURES_DIR / fixture_name
    env = dict(os.environ, HOME=str(unmarked_home))

    proc = subprocess.run(
        [sys.executable, str(fixture_script)],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode != 0, f"{fixture_name} did not exit with an error outside fake home"
    combined_output = proc.stdout + proc.stderr
    assert "SAFETY ERROR" in combined_output
    assert ".trapdoor-fake-home" in combined_output


def test_fixture_credential_theft(tmp_path):
    """Credential theft: reads fake ~/.ssh/id_ed25519.

    Strict acceptance assertion: triggers *exactly* {'secret-access'} and
    no other rule.
    """
    fake_home = tmp_path / "fakehome"
    ssh_dir = fake_home / ".ssh"
    ssh_dir.mkdir(parents=True)
    fake_key = ssh_dir / "id_ed25519"
    fake_key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")

    triggered_rule_ids, hits = run_fixture("credential_theft.py", tmp_path, fake_home=fake_home)

    # Strict set equality
    assert triggered_rule_ids == {"secret-access"}
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert "id_ed25519" in hits[0].message


def test_fixture_beacon(tmp_path):
    """Beacon: connects to network endpoint.

    Strict acceptance assertion: triggers *exactly* {'unexpected-network'}.
    """
    fake_home = tmp_path / "fakehome"
    triggered_rule_ids, hits = run_fixture("beacon.py", tmp_path, fake_home=fake_home)

    # Strict set equality
    assert triggered_rule_ids == {"unexpected-network"}
    assert len(hits) == 1
    assert hits[0].severity == "low"  # loopback connect gets loopback_severity (low)


def test_fixture_fetch_and_execute(tmp_path):
    """Fetch-and-execute: drops a script in project and executes it.

    Strict acceptance assertion: triggers *exactly* {'fetch-and-execute'}.
    """
    fake_home = tmp_path / "fakehome"
    triggered_rule_ids, hits = run_fixture("fetch_and_execute.py", tmp_path, fake_home=fake_home)

    # Strict set equality
    assert triggered_rule_ids == {"fetch-and-execute"}
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_fixture_persistence(tmp_path):
    """Persistence: appends hook to shell startup (~/.bashrc).

    Strict acceptance assertion: triggers *exactly* {'persistence', 'write-outside-project'}.
    """
    fake_home = tmp_path / "fakehome"
    fake_home.mkdir(parents=True, exist_ok=True)
    (fake_home / ".bashrc").write_text("# existing bashrc\n")

    triggered_rule_ids, hits = run_fixture("persistence.py", tmp_path, fake_home=fake_home)

    # Strict set equality: triggers both persistence and write-outside-project
    assert triggered_rule_ids == {"persistence", "write-outside-project"}
    persistence_hits = [h for h in hits if h.rule_id == "persistence"]
    assert len(persistence_hits) == 1
    assert persistence_hits[0].severity == "high"
    assert ".bashrc" in persistence_hits[0].message
    outside_hits = [h for h in hits if h.rule_id == "write-outside-project"]
    assert len(outside_hits) == 1
    assert outside_hits[0].severity == "low"


def test_fixture_clean_control(tmp_path):
    """Clean control: ordinary build work strictly inside project.

    Strict acceptance assertion: triggers *exactly* zero rules (empty set).
    """
    fake_home = tmp_path / "fakehome"
    triggered_rule_ids, hits = run_fixture("clean_control.py", tmp_path, fake_home=fake_home)

    # Strict set equality: clean run must produce zero hits
    assert triggered_rule_ids == set()
    assert hits == []
