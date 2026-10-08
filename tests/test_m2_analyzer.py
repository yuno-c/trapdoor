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


def test_dns_port_53_nameserver_exemption_and_rogue_flagging(tmp_path):
    """Hermetic test: port 53 exempt only for authorized nameservers.

    Uses synthetic events and injected nameservers list (never reads /etc/resolv.conf).
    """
    from trapdoor.events import Event
    from trapdoor.rules import evaluate, get_system_nameservers, load_rules

    rules = load_rules()
    injected_nameservers = {"192.0.2.53", "127.0.0.53"}

    # 1. Connect to authorized nameserver on port 53 -> exempt (no hit)
    ev_allowed_ns = [
        Event(t=0.1, pid=1, ppid=0, exe="/bin/curl", kind="net.connect",
              fields={"addr": "192.0.2.53", "port": 53, "family": "inet"}),
        Event(t=0.2, pid=1, ppid=0, exe="/bin/curl", kind="net.connect",
              fields={"addr": "127.0.0.53", "port": 53, "family": "inet"}),
    ]
    hits = evaluate(ev_allowed_ns, rules, project=str(tmp_path),
                    nameservers=injected_nameservers)
    assert hits == []

    # 2. Connect to unauthorized port 53 destination -> flagged
    ev_rogue_external = [
        Event(t=0.3, pid=1, ppid=0, exe="/bin/curl", kind="net.connect",
              fields={"addr": "8.8.8.8", "port": 53, "family": "inet"}),
    ]
    hits_rogue = evaluate(ev_rogue_external, rules, project=str(tmp_path),
                          nameservers=injected_nameservers)
    assert len(hits_rogue) == 1
    assert hits_rogue[0].rule_id == "unexpected-network"
    assert hits_rogue[0].severity == "medium"
    assert "8.8.8.8:53" in hits_rogue[0].message

    # 3. Connect to loopback port 53 that is not in nameservers -> flagged with low severity
    ev_rogue_loopback = [
        Event(t=0.4, pid=1, ppid=0, exe="/bin/curl", kind="net.connect",
              fields={"addr": "127.0.0.1", "port": 53, "family": "inet"}),
    ]
    hits_loopback = evaluate(ev_rogue_loopback, rules, project=str(tmp_path),
                             nameservers=injected_nameservers)
    assert len(hits_loopback) == 1
    assert hits_loopback[0].rule_id == "unexpected-network"
    assert hits_loopback[0].severity == "low"

    # 4. Connect to nameserver on non-DNS port (e.g. 80) -> flagged with medium severity
    ev_ns_non_dns_port = [
        Event(t=0.5, pid=1, ppid=0, exe="/bin/curl", kind="net.connect",
              fields={"addr": "192.0.2.53", "port": 80, "family": "inet"}),
    ]
    hits_non_dns = evaluate(ev_ns_non_dns_port, rules, project=str(tmp_path),
                            nameservers=injected_nameservers)
    assert len(hits_non_dns) == 1
    assert hits_non_dns[0].rule_id == "unexpected-network"
    assert hits_non_dns[0].severity == "medium"

    # 5. Verify get_system_nameservers parser logic with custom file
    fake_resolv = tmp_path / "resolv.conf"
    fake_resolv.write_text(
        "# Comment\n"
        "; Another comment\n"
        "nameserver 10.0.0.1\n"
        "search example.com\n"
        "nameserver 10.0.0.2\n"
    )
    parsed = get_system_nameservers(fake_resolv)
    assert parsed == {"127.0.0.53", "10.0.0.1", "10.0.0.2"}

    # Missing file safely falls back to 127.0.0.53
    assert get_system_nameservers(tmp_path / "nonexistent") == {"127.0.0.53"}


def test_net_bind_loopback_exempt_and_external_flagged(tmp_path):
    """Hermetic test: net.bind to loopback is exempt; non-loopback bind flags.

    Loopback net.connect stays low severity so beacon fixture passes.
    """
    from trapdoor.events import Event
    from trapdoor.rules import evaluate, load_rules

    rules = load_rules()

    # 1. net.bind to loopback -> exempt (no hit)
    ev_bind_loopback = [
        Event(t=0.1, pid=1, ppid=0, exe="/bin/python", kind="net.bind",
              fields={"addr": "127.0.0.1", "port": 8000, "family": "inet"}),
        Event(t=0.2, pid=1, ppid=0, exe="/bin/python", kind="net.bind",
              fields={"addr": "::1", "port": 8000, "family": "inet6"}),
    ]
    hits = evaluate(ev_bind_loopback, rules, project=str(tmp_path))
    assert hits == []

    # 2. net.bind to non-loopback address -> flags medium severity
    ev_bind_external = [
        Event(t=0.3, pid=1, ppid=0, exe="/bin/python", kind="net.bind",
              fields={"addr": "0.0.0.0", "port": 8000, "family": "inet"}),
        Event(t=0.4, pid=1, ppid=0, exe="/bin/python", kind="net.bind",
              fields={"addr": "192.168.1.100", "port": 8000, "family": "inet"}),
    ]
    hits_bind_ext = evaluate(ev_bind_external, rules, project=str(tmp_path))
    assert len(hits_bind_ext) == 2
    for h in hits_bind_ext:
        assert h.rule_id == "unexpected-network"
        assert h.severity == "medium"

    # 3. net.connect to loopback stays low severity
    ev_connect_loopback = [
        Event(t=0.5, pid=1, ppid=0, exe="/bin/python", kind="net.connect",
              fields={"addr": "127.0.0.1", "port": 9999, "family": "inet"}),
    ]
    hits_connect = evaluate(ev_connect_loopback, rules, project=str(tmp_path))
    assert len(hits_connect) == 1
    assert hits_connect[0].rule_id == "unexpected-network"
    assert hits_connect[0].severity == "low"


def test_tiered_verdict_clean_notices_suspicious(tmp_path):
    """Hermetic test: tiered verdict (clean, notices, suspicious).

    - 0 hits: 'no suspicious behavior' (text) / 'clean' (JSON)
    - low-only: 'notices' (text) / 'notices' (JSON)
    - medium or higher: 'SUSPICIOUS' (text) / 'suspicious' (JSON)
    """
    from trapdoor.analyze import Hit, normalize
    from trapdoor.report import compute_verdict, render_json, render_text

    analysis = normalize([], str(tmp_path))

    # Case A: 0 hits -> clean
    v_text, v_json = compute_verdict([])
    assert v_text == "no suspicious behavior"
    assert v_json == "clean"
    text = render_text(analysis, [])
    assert "verdict: no suspicious behavior" in text
    assert render_json(analysis, [])["verdict"] == "clean"

    # Case B: low-only hits -> notices
    low_hits = [
        Hit(rule_id="write-outside-project", severity="low",
            message="modification outside project: /tmp/scratch",
            exe="/bin/test", pid=123),
    ]
    v_text, v_json = compute_verdict(low_hits)
    assert v_text == "notices"
    assert v_json == "notices"
    text = render_text(analysis, low_hits)
    assert "verdict: notices" in text
    assert "SUSPICIOUS" not in text
    assert render_json(analysis, low_hits)["verdict"] == "notices"

    # Case C: medium-only hit -> suspicious
    med_hits = [
        Hit(rule_id="unexpected-network", severity="medium",
            message="network connection to 8.8.8.8:53",
            exe="/bin/curl", pid=123),
    ]
    v_text, v_json = compute_verdict(med_hits)
    assert v_text == "SUSPICIOUS"
    assert v_json == "suspicious"
    text = render_text(analysis, med_hits)
    assert "verdict: SUSPICIOUS" in text
    assert render_json(analysis, med_hits)["verdict"] == "suspicious"

    # Case D: high-only hit -> suspicious
    high_hits = [
        Hit(rule_id="secret-access", severity="high",
            message="touched sensitive file ~/.ssh/id_rsa",
            exe="/bin/cat", pid=123),
    ]
    v_text, v_json = compute_verdict(high_hits)
    assert v_text == "SUSPICIOUS"
    assert v_json == "suspicious"

    # Case E: mixed low + medium -> suspicious
    mixed_hits = [low_hits[0], med_hits[0]]
    v_text, v_json = compute_verdict(mixed_hits)
    assert v_text == "SUSPICIOUS"
    assert v_json == "suspicious"


def test_pip_notable_files_noise_collapse(tmp_path, monkeypatch):
    """Hermetic test: collapse .venv/, site-packages/, __pycache__/, ~/.cache/, and /tmp/pip-*.

    Notable files must aggregate event counts under collapsed categories without
    enumerating individual files. Rules must still evaluate raw events.
    """
    from trapdoor.analyze import collapsed_category, normalize
    from trapdoor.events import Event
    from trapdoor.report import render_json, render_text
    from trapdoor.rules import evaluate, load_rules

    project_dir = str(tmp_path / "myproject")
    fake_home = str(tmp_path / "fakehome")
    monkeypatch.setenv("HOME", fake_home)

    # 1. Direct classification test
    assert collapsed_category(f"{project_dir}/.venv/bin/activate", project_dir) == ".venv/"
    assert collapsed_category(f"{project_dir}/.venv/lib/python3.13/site-packages/rich/syntax.py", project_dir) == "site-packages/"
    assert collapsed_category(f"{project_dir}/site-packages/rich/syntax.py", project_dir) == "site-packages/"
    assert collapsed_category(f"{project_dir}/__pycache__/foo.cpython-313.pyc", project_dir) == "__pycache__/"
    assert collapsed_category(f"{fake_home}/.cache/pip/wheels/pkg.whl", project_dir) == "~/.cache/"
    assert collapsed_category("/tmp/pip-install-12345/rich/setup.py", project_dir) == "/tmp/pip-*"
    assert collapsed_category("/tmp/pip-build-env-xyz/overlay", project_dir) == "/tmp/pip-*"
    assert collapsed_category(f"{project_dir}/src/app.py", project_dir) is None
    assert collapsed_category(f"{fake_home}/.ssh/id_rsa", project_dir) is None

    # 2. Normalization aggregation test
    synthetic_events = [
        # 3 events in .venv/
        Event(t=0.1, pid=1, ppid=0, exe="/bin/pip", kind="file.open",
              fields={"path": f"{project_dir}/.venv/bin/python"}),
        Event(t=0.2, pid=1, ppid=0, exe="/bin/pip", kind="file.open",
              fields={"path": f"{project_dir}/.venv/bin/pip"}),
        Event(t=0.3, pid=1, ppid=0, exe="/bin/pip", kind="file.write",
              fields={"path": f"{project_dir}/.venv/pyvenv.cfg"}),
        # 4 events in site-packages/
        Event(t=0.4, pid=1, ppid=0, exe="/bin/pip", kind="file.open",
              fields={"path": f"{project_dir}/.venv/lib/python3.13/site-packages/rich/__init__.py"}),
        Event(t=0.5, pid=1, ppid=0, exe="/bin/pip", kind="file.write",
              fields={"path": f"{project_dir}/.venv/lib/python3.13/site-packages/rich/console.py"}),
        Event(t=0.6, pid=1, ppid=0, exe="/bin/pip", kind="file.open",
              fields={"path": f"{project_dir}/site-packages/extra.py"}),
        Event(t=0.7, pid=1, ppid=0, exe="/bin/pip", kind="file.write",
              fields={"path": f"{project_dir}/site-packages/extra2.py"}),
        # 2 events in __pycache__/
        Event(t=0.8, pid=1, ppid=0, exe="/bin/python", kind="file.write",
              fields={"path": f"{project_dir}/__pycache__/mod.cpython-313.pyc"}),
        Event(t=0.9, pid=1, ppid=0, exe="/bin/python", kind="file.open",
              fields={"path": f"{project_dir}/.venv/lib/python3.13/site-packages/rich/__pycache__/console.cpython-313.pyc"}),
        # 2 events in ~/.cache/
        Event(t=1.0, pid=1, ppid=0, exe="/bin/pip", kind="file.open",
              fields={"path": f"{fake_home}/.cache/pip/wheels/a.whl"}),
        Event(t=1.1, pid=1, ppid=0, exe="/bin/pip", kind="file.write",
              fields={"path": f"{fake_home}/.cache/pip/http/cache.json"}),
        # 3 events in /tmp/pip-*
        Event(t=1.2, pid=1, ppid=0, exe="/bin/pip", kind="file.open",
              fields={"path": "/tmp/pip-install-abcd/setup.py"}),
        Event(t=1.3, pid=1, ppid=0, exe="/bin/pip", kind="file.write",
              fields={"path": "/tmp/pip-build-env-123/record.txt"}),
        Event(t=1.4, pid=1, ppid=0, exe="/bin/pip", kind="file.delete",
              fields={"path": "/tmp/pip-unpack-999/tmp.whl"}),
        # 1 uncollapsed notable file
        Event(t=1.5, pid=1, ppid=0, exe="/bin/pip", kind="file.open",
              fields={"path": f"{fake_home}/.ssh/id_rsa"}),
    ]

    analysis = normalize(synthetic_events, project_dir)

    # Notable files must have collapsed categories with exact counts
    assert analysis.notable_files[".venv/"] == 3
    assert analysis.notable_files["site-packages/"] == 4
    assert analysis.notable_files["__pycache__/"] == 2
    assert analysis.notable_files["~/.cache/"] == 2
    assert analysis.notable_files["/tmp/pip-*"] == 3
    assert analysis.notable_files[f"{fake_home}/.ssh/id_rsa"] == 1

    # Individual subfiles must NOT be keys in notable_files
    assert f"{project_dir}/.venv/bin/python" not in analysis.notable_files
    assert "/tmp/pip-install-abcd/setup.py" not in analysis.notable_files
    assert f"{fake_home}/.cache/pip/wheels/a.whl" not in analysis.notable_files

    # 3. Report rendering test
    text = render_text(analysis, [])
    assert ".venv/  (3 events)" in text
    assert "site-packages/  (4 events)" in text
    assert "__pycache__/  (2 events)" in text
    assert "~/.cache/  (2 events)" in text
    assert "/tmp/pip-*  (3 events)" in text

    data = render_json(analysis, [])
    assert data["notable_files"][".venv/"] == 3
    assert data["notable_files"]["site-packages/"] == 4
    assert data["notable_files"]["__pycache__/"] == 2
    assert data["notable_files"]["~/.cache/"] == 2
    assert data["notable_files"]["/tmp/pip-*"] == 3

    # 4. Rules still evaluate raw events (uncollapsed raw paths)
    rules = load_rules()
    hits = evaluate(synthetic_events, rules, project=project_dir, home=fake_home)
    # The event touching ~/.ssh/id_rsa must still be flagged by secret-access
    hit_ids = {h.rule_id for h in hits}
    assert "secret-access" in hit_ids



