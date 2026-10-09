"""Trapdoor CLI (M2: run | rules list; diff arrives in M5)."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from trapdoor.analyze import normalize
from trapdoor.events import EventStreamError, load_events
from trapdoor.report import render_json, render_text
from trapdoor.rules import evaluate, load_rules, resolve_allowed_hosts


def find_tracer() -> Path | None:
    """Locate the trapdoor-trace binary. Returns None if not found."""
    env = os.environ.get("TRAPDOOR_TRACE_BIN")
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    here = Path(__file__).resolve()
    # <root>/src/trapdoor/cli.py -> <root> is parents[2]
    root = here.parents[2] if len(here.parents) >= 3 else Path.cwd()
    for cand in (
        root / "build" / "tracer" / "trapdoor-trace",
        root / "build" / "trapdoor-trace",
        Path.cwd() / "build" / "tracer" / "trapdoor-trace",
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    found = shutil.which("trapdoor-trace")
    return Path(found) if found else None


def _run_trace(tracer: Path, events_path: Path, argv: list[str]) -> int:
    tracer_args = [str(tracer)]
    if os.environ.get("TRAPDOOR_TRACE_STATS"):
        tracer_args.append("--stats")
    tracer_args.extend(["-o", str(events_path), "--", *argv])
    proc = subprocess.run(tracer_args)
    return proc.returncode


def _has_external_network(events: list) -> bool:
    """True if stream contains any non-loopback inet/inet6 network events."""
    for e in events:
        if e.kind in ("net.connect", "net.bind"):
            if str(e.get("family", "")) in ("inet", "inet6"):
                addr = str(e.get("addr", ""))
                if not (addr.startswith("127.") or addr in ("::1", "localhost")):
                    return True
    return False


def cmd_run(argv: list[str], *, output: str | None, as_json: bool,
            keep_events: bool, allow_ips: list[str] | None = None,
            allowed_ips: set[str] | None = None,
            nameservers: set[str] | None = None) -> int:
    tracer = find_tracer()
    if tracer is None:
        print("error: trapdoor-trace binary not found. Build it: "
              "cmake -S . -B build && cmake --build build -j, "
              "or set TRAPDOOR_TRACE_BIN.", file=sys.stderr)
        return 2
    if not argv:
        print("usage: trapdoor run -- <command> [args...]", file=sys.stderr)
        return 2
    if argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("usage: trapdoor run -- <command> [args...]", file=sys.stderr)
        return 2

    # `-o` always names the raw event stream (the tracer writes it); the
    # human/JSON report goes to stdout either way.
    events_path = Path(output) if output else None
    own_stream = events_path is None
    if own_stream:
        # Temp stream; we still write the final JSON report separately.
        import tempfile

        tmp = tempfile.NamedTemporaryFile(
            prefix="trapdoor-events-", suffix=".jsonl", delete=False)
        tmp.close()
        events_path = Path(tmp.name)

    assert events_path is not None
    rc = _run_trace(tracer, events_path, argv)

    try:
        events = load_events(events_path)
    except EventStreamError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    project = str(Path.cwd())
    analysis = normalize(events, project)

    # Lazy DNS resolution: only query registry hosts if the trace contains
    # non-loopback network traffic and allowed_ips was not injected.
    env_ips = os.environ.get("TRAPDOOR_ALLOWED_IPS")
    cli_ips = set(allow_ips or [])
    if allowed_ips is not None:
        effective_allowed = set(allowed_ips) | cli_ips
        override_source = "--allow-ip / injected"
    elif cli_ips:
        effective_allowed = cli_ips
        override_source = "--allow-ip"
    elif env_ips is not None:
        effective_allowed = {ip.strip() for ip in env_ips.split(",") if ip.strip()}
        override_source = "TRAPDOOR_ALLOWED_IPS env"
    elif _has_external_network(events):
        resolved_ips, failed_hosts = resolve_allowed_hosts()
        effective_allowed = resolved_ips
        override_source = None
        if not resolved_ips and failed_hosts:
            analysis.warnings.append(
                "registry allowlist was unavailable: DNS resolution failed "
                f"(could not resolve: {', '.join(sorted(failed_hosts))})"
            )
        elif failed_hosts:
            analysis.warnings.append(
                "registry allowlist partially unavailable: DNS resolution failed for "
                f"{', '.join(sorted(failed_hosts))}"
            )
    else:
        effective_allowed = set()
        override_source = None

    if override_source and effective_allowed:
        analysis.warnings.append(
            f"allowlist override active ({override_source}): "
            f"network detections suppressed for {', '.join(sorted(effective_allowed))}"
        )

    try:
        rules = load_rules()
    except (FileNotFoundError, ValueError) as e:
        print(f"error: rules invalid: {e}", file=sys.stderr)
        return 2
    hits = evaluate(events, rules, project, allowed_ips=effective_allowed,
                    nameservers=nameservers)
    analysis.hits = hits

    if as_json:
        json.dump(render_json(analysis, hits), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(analysis, hits))

    if keep_events and own_stream:
        print(f"# events kept at: {events_path}", file=sys.stderr)
    if own_stream and not keep_events:
        try:
            events_path.unlink()
        except OSError:
            pass

    if rc != 0:
        # A failed trace must never look like a clean result.
        print(f"note: traced command exited with {rc}.", file=sys.stderr)
        return rc
    return 0


def cmd_rules(argv: list[str]) -> int:
    if argv and argv[0] == "list":
        rules = load_rules()
        for r in rules:
            print(f"[{r['severity']}] {r['id']}  ({r['type']})")
            print(f"    {r.get('description', '')}")
        return 0
    print("usage: trapdoor rules list", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="trapdoor",
        description="Trapdoor: Install-Time Behavior Auditor.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Run a command under the tracer.")
    p_run.add_argument("-o", "--output", default=None,
                       help="Keep the raw JSONL event stream at this path.")
    p_run.add_argument("--json", action="store_true",
                       help="Emit the report as JSON instead of terminal text.")
    p_run.add_argument("--keep-events", action="store_true",
                       help="Keep the temporary event stream for debugging.")
    p_run.add_argument("--allow-ip", action="append", default=[], dest="allow_ips",
                       help="Explicitly allow an IP address (suppresses unexpected-network hits).")
    p_run.add_argument(
        "target", nargs=argparse.REMAINDER,
        help="Use -- to separate: run -- <cmd> [...]"
    )

    sub.add_parser("diff", help="(M5) diff behavior fingerprints.")
    p_rules = sub.add_parser("rules", help="Inspect the rule set.")
    p_rules.add_argument("action", nargs=argparse.REMAINDER,
                         help="`list` prints the loaded rules.")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    ns = ap.parse_args(argv)
    if ns.cmd == "run":
        return cmd_run(list(ns.target), output=ns.output,
                       as_json=ns.json, keep_events=ns.keep_events,
                       allow_ips=ns.allow_ips)
    if ns.cmd == "rules":
        return cmd_rules(list(ns.action))
    print(f"error: '{ns.cmd}' is not implemented yet.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
