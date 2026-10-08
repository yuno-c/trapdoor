"""Human-readable terminal report. Kept boring on purpose: a security
tool that prints colored surprises erodes trust. ASCII only."""

from __future__ import annotations

from pathlib import Path

from trapdoor.analyze import Analysis, Hit, ProcessNode, flatten


def _walk(nodes: list[ProcessNode], depth: int = 0,
          out: list[str] | None = None) -> list[str]:
    if out is None:
        out = []
    for n in nodes:
        out.append(f"{'  ' * depth}{n.argv0 or Path(n.exe).name} (pid {n.pid})")
        _walk(n.children, depth + 1, out)
    return out


def _plural(n: int, singular: str) -> str:
    return f"{n} {singular}" + ("" if n == 1 else "s")


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def compute_verdict(hits: list[Hit]) -> tuple[str, str]:
    """Compute tiered verdict for report rendering.

    Returns (text_verdict, json_verdict).
    - SUSPICIOUS / "suspicious" only for medium or higher (rank >= 2)
    - notices / "notices" when hits are low or info only (rank < 2)
    - no suspicious behavior / "clean" when there are zero hits
    """
    if not hits:
        return "no suspicious behavior", "clean"
    if any(SEVERITY_RANK.get(h.severity, 0) >= 2 for h in hits):
        return "SUSPICIOUS", "suspicious"
    return "notices", "notices"


def render_text(analysis: Analysis, hits: list[Hit]) -> str:
    lines: list[str] = []
    lines.append("trapdoor report")
    lines.append("===============")
    lines.append("")
    v_text, _ = compute_verdict(hits)
    lines.append(f"verdict: {v_text}")
    lines.append("")

    if analysis.warnings:
        lines.append("warnings")
        lines.append("--------")
        for w in analysis.warnings:
            lines.append(f"  warning: {w}")
        lines.append("")

    lines.append("process tree")
    lines.append("------------")
    for root in analysis.processes:
        lines.extend(_walk([root]))
    lines.append("")

    lines.append("network endpoints")
    lines.append("-----------------")
    if not analysis.network:
        lines.append("  (none)")
    else:
        for exe, addr, port in analysis.network:
            lines.append(f"  {addr}:{port}  <- {Path(exe).name}")
    lines.append("")

    lines.append("notable files (outside node_modules/.git/caches)")
    lines.append("-----------------------------------------------")
    if not analysis.notable_files:
        lines.append("  (none)")
    else:
        for p, c in sorted(analysis.notable_files.items()):
            lines.append(f"  {p}  ({_plural(c, 'event')})")
    lines.append("")

    lines.append("rule hits")
    lines.append("---------")
    if not hits:
        lines.append("  (none)")
    else:
        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        by_sev = sorted(hits, key=lambda h: severity_order[h.severity])
        for h in by_sev:
            lines.append(f"  [{h.severity}] {h.rule_id}: {h.message}")
            lines.append(f"         ({Path(h.exe).name or h.exe}, pid {h.pid})")
    lines.append("")

    lines.append("event mix")
    lines.append("---------")
    for kind, count in sorted(analysis.event_counts.items()):
        lines.append(f"  {kind:<12} {count}")
    lines.append("")

    lines.append("note: v1 observes only; it does not block. Observed-clean means")
    lines.append("no suspicious behavior in this run. See README for the threat model.")
    return "\n".join(lines) + "\n"


def render_json(analysis: Analysis, hits: list[Hit]) -> dict:
    _, v_json = compute_verdict(hits)
    return {
        "verdict": v_json,
        "project": analysis.project,
        "warnings": analysis.warnings,
        "network": [
            {"exe": exe, "addr": addr, "port": port}
            for exe, addr, port in analysis.network
        ],
        "notable_files": analysis.notable_files,
        "hits": [
            {
                "rule_id": h.rule_id,
                "severity": h.severity,
                "message": h.message,
                "exe": h.exe,
                "pid": h.pid,
            }
            for h in hits
        ],
        "event_counts": dict(analysis.event_counts),
        "process_tree": [
            {"pid": n.pid, "ppid": n.ppid, "exe": n.exe, "argv0": n.argv0}
            for n in flatten(analysis.processes)
        ],
    }
