"""Rule engine: declarative rules from rules.toml applied to the stream.

Each finding is severity-ranked, one sentence, attributed to the
process (pid + exe) that caused it. False-positive control is explicit:
the registry host is allowed for inet connects, loopback is low, and the
expected build noise areas never raise findings.
"""

from __future__ import annotations

import os
import socket
import tomllib
from pathlib import Path

from trapdoor.analyze import Hit
from trapdoor.events import Event

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}

# Hosts whose install-time traffic is expected: the package registry and
# its CDNs. Matched on suffix so scoped mirrors (registry.npmjs.org etc.)
# stay allowed without enumerating them.
REGULAR_HOSTS = (
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.yarnpkg.com",
    "registry.npmjs.com",
)

DOWNLOAD_TOOL_BASENAMES = ("curl", "wget", "nc", "ncat", "openssl")


def _expand(spec: str, home: str | None = None) -> str:
    if home is not None:
        # Manual expansion using the tracee's HOME, not os.path.expanduser
        if spec.startswith("~/"):
            return home + spec[1:]
        if spec == "~":
            return home
    return os.path.expanduser(os.path.expandvars(spec))


import threading
import time


def resolve_allowed_hosts(timeout: float = 2.0) -> tuple[set[str], list[str]]:
    """Forward-resolve REGULAR_HOSTS into a set of IP addresses.

    Resolves hosts concurrently with daemon threads and a strict timeout.
    Daemon threads ensure that slow or uncancelable getaddrinfo calls never
    block returning from this function or hang the process at exit.
    Returns (resolved_ips, failed_hosts).
    """
    results: dict[str, set[str]] = {}
    errors: dict[str, bool] = {}

    def _worker(host: str) -> None:
        try:
            ips: set[str] = set()
            for info in socket.getaddrinfo(host, None, socket.AF_UNSPEC,
                                           socket.SOCK_STREAM):
                ips.add(info[4][0])
            results[host] = ips
        except Exception:
            errors[host] = True

    threads: list[tuple[str, threading.Thread]] = []
    for host in REGULAR_HOSTS:
        t = threading.Thread(target=_worker, args=(host,), daemon=True)
        t.start()
        threads.append((host, t))

    deadline = time.monotonic() + timeout
    for host, t in threads:
        rem = deadline - time.monotonic()
        if rem > 0:
            t.join(rem)

    resolved: set[str] = set()
    failed: list[str] = []
    for host, t in threads:
        if t.is_alive() or host in errors or host not in results:
            failed.append(host)
        else:
            resolved.update(results[host])

    return resolved, failed


def find_rules_file() -> Path:
    here = Path(__file__).resolve().parent
    candidate = here / "rules.toml"
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(
        f"rules.toml not found next to {__file__}; packaging error")


def load_rules(path: str | Path | None = None) -> list[dict]:
    p = Path(path) if path else find_rules_file()
    with p.open("rb") as f:
        data = tomllib.load(f)
    rules = data.get("rule", [])
    if not rules:
        raise ValueError(f"{p}: no [[rule]] entries")
    for r in rules:
        if "id" not in r or "type" not in r or "severity" not in r:
            raise ValueError(f"{p}: rule missing id/type/severity: {r}")
    return rules


def _matches_any(path: str, prefixes: list[str], home: str | None = None) -> bool:
    for raw in prefixes:
        p = _expand(raw, home).rstrip("/")
        if raw.endswith("/"):
            if path == p or path.startswith(p + "/"):
                return True
        else:
            if path == p:
                return True
    return False


def _is_in_ignore(path: str, ignore: list[str], home: str | None = None) -> bool:
    is_under_home = False
    if home is not None:
        norm_home = home.rstrip("/")
        is_under_home = (path == norm_home) or path.startswith(norm_home + "/")

    for raw in ignore:
        # If the path is inside the user's home directory, system-wide /tmp
        # scratch exemptions do not apply (e.g. tests running with HOME in /tmp).
        if is_under_home and raw.rstrip("/") == "/tmp":
            continue
        p = _expand(raw, home).rstrip("/")
        if raw.endswith("/"):
            if path == p or path.startswith(p + "/"):
                return True
        elif path == p:
            return True
    return False


def _write_event(e: Event) -> bool:
    """Reads that also write, creates, or truncations count as writes."""
    if e.kind == "file.write":
        return True
    if e.kind in ("file.delete", "file.rename"):
        return True
    if e.kind == "file.open":
        flags = str(e.get("flags", ""))
        return any(
            bit in flags
            for bit in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND",
                        "O_TMPFILE"))
    return False


def evaluate(events: list[Event], rules: list[dict], project: str,
             allowed_ips: set[str] | None = None,
             home: str | None = None) -> list[Hit]:
    hits: list[Hit] = []
    written: list[tuple[Event, str]] = []
    for e in events:
        if e.kind in ("file.open", "file.write", "file.delete", "file.rename"):
            if _write_event(e):
                written.append((e, str(e.get("path", e.get("src", "")))))

    for rule in rules:
        rtype = rule["type"]
        rid = rule["id"]
        if rtype == "sensitive_read":
            for e in events:
                if e.kind not in ("file.open", "file.write",
                                  "file.delete", "file.rename"):
                    continue
                path = str(e.get("path", e.get("src", "")))
                if _matches_any(path, rule.get("paths", []), home):
                    hits.append(Hit(
                        rule_id=rid, severity=rule["severity"],
                        message=rule["message"].format(path=path),
                        exe=e.exe, pid=e.pid, sample=e))

        elif rtype == "network":
            for e in events:
                if e.kind not in ("net.connect", "net.bind"):
                    continue
                if str(e.get("family", "")) not in ("inet", "inet6"):
                    continue
                addr = str(e.get("addr", "?"))
                port = e.get("port", 0)
                # Traffic to known registry IPs is expected install behavior (no hit).
                if allowed_ips is not None and addr in allowed_ips:
                    continue
                if addr.startswith("127.") or addr in ("::1", "localhost"):
                    sev = rule.get("loopback_severity", "low")
                else:
                    sev = rule["severity"]
                hits.append(Hit(
                    rule_id=rid, severity=sev,
                    message=rule["message"].format(addr=addr, port=port),
                    exe=e.exe, pid=e.pid, sample=e))

        elif rtype == "write_then_exec":
            for exec_e in events:
                if exec_e.kind != "proc.exec":
                    continue
                target = str(exec_e.get("path", ""))
                if not target:
                    continue
                for w_e, w_path in written:
                    if w_path and w_path == target:
                        hits.append(Hit(
                            rule_id=rid, severity=rule["severity"],
                            message=rule["message"].format(path=target),
                            exe=exec_e.exe, pid=exec_e.pid, sample=exec_e))
                        break

        elif rtype == "tool_exec":
            tools = rule.get("tools", list(DOWNLOAD_TOOL_BASENAMES))
            for e in events:
                if e.kind != "proc.exec":
                    continue
                argv = e.get("argv") or []
                name = os.path.basename(str(argv[0])) if argv else ""
                if not name:
                    name = os.path.basename(e.exe)
                if name in tools:
                    hits.append(Hit(
                        rule_id=rid, severity=rule["severity"],
                        message=rule["message"].format(name=name),
                        exe=e.exe, pid=e.pid, sample=e))

        elif rtype == "path_write":
            for e, w_path in [(e, p) for e, p in written]:
                if _matches_any(w_path, rule.get("paths", []), home):
                    hits.append(Hit(
                        rule_id=rid, severity=rule["severity"],
                        message=rule["message"].format(path=w_path),
                        exe=e.exe, pid=e.pid, sample=e))

        elif rtype == "external_write":
            ignore = rule.get("ignore_prefixes", [])
            project_ok = os.path.abspath(project)
            for e, w_path in written:
                if not w_path:
                    continue
                if _is_in_ignore(w_path, ignore, home):
                    continue
                if os.path.abspath(w_path).startswith(project_ok + os.sep):
                    continue
                hits.append(Hit(
                    rule_id=rid, severity=rule["severity"],
                    message=rule["message"].format(path=w_path),
                    exe=e.exe, pid=e.pid, sample=e))
        else:
            raise ValueError(f"{rid}: unknown rule type {rtype!r}")

    # Stable, severity-first, deterministic order for reproducible reports.
    hits.sort(key=lambda h: (-SEVERITY_RANK[h.severity], h.rule_id, h.pid))
    seen: set[tuple[str, int, str]] = set()
    unique: list[Hit] = []
    for h in hits:
        key = (h.rule_id, h.pid, h.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(h)
    return unique
