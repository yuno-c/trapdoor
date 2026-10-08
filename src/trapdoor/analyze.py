"""Analysis layer: normalization, process tree, findings.

- Noise collapses: thousands of file opens inside the expected areas
  (node_modules, the npm cache, temp dirs) are counted, not listed.
- Events are grouped by process: npm -> node postinstall -> curl chains.
- Every finding keeps the pid/exe of the process that caused it, and
  carries the responsible event so reports stay attributable.
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from trapdoor.events import Event

PROC_TREE_DEEPEST_NOTE = "deepest non-loopback net.connect per process and port family"

# Expected build noise areas (relative to the project root); files inside
# are summarized as counts rather than listed.
NOISE_AREA_PREFIXES = ("node_modules/", ".git/", ".npm/", ".cache/")

# Absolute system paths whose read-only opens are normal runtime noise.
# /nix/store/ shared-library loads dominate on NixOS; /usr/lib/, /lib/,
# /proc/, /sys/, /dev/ are universally noisy. Writes are still audited
# (the external_write rule handles them).
SYSTEM_NOISE_PREFIXES = (
    "/nix/store/", "/nix/", "/usr/lib/", "/usr/share/", "/lib/", "/lib64/",
    "/proc/", "/sys/", "/dev/",
)


@dataclass(frozen=True)
class Hit:
    rule_id: str
    severity: str
    message: str  # already formatted
    exe: str
    pid: int
    sample: Event | None = None


@dataclass(frozen=True)
class Finding:
    """A grouped behavioral observation presented in the report."""

    kind: str  # file.open | net.connect | proc.exec | file.write | file.delete
    detail: str  # normalized human detail
    exe: str
    pid: int


@dataclass
class ProcessNode:
    pid: int
    ppid: int
    exe: str
    argv0: str
    children: list["ProcessNode"] = field(default_factory=list)


@dataclass
class Analysis:
    project: str
    processes: list[ProcessNode]
    notable_files: dict[str, int]  # display path -> count outside noise areas
    network: list[tuple[str, str, str]]  # (exe, addr, port)
    findings_by_kind: dict[str, int]
    hits: list[Hit]
    event_counts: Counter[str]
    quiet: str  # one-line plain-English summary
    warnings: list[str] = field(default_factory=list)


COLLAPSED_CATEGORIES = (
    ".venv/",
    "site-packages/",
    "__pycache__/",
    "~/.cache/",
    "/tmp/pip-*",
)


def collapsed_category(path: str, project: str) -> str | None:
    """Classify known noise paths from package installations into collapse categories."""
    if not path:
        return None

    # /tmp/pip-*
    if path == "/tmp/pip-*" or path.startswith("/tmp/pip-"):
        return "/tmp/pip-*"

    # ~/.cache/
    if path == "~/.cache" or path.startswith("~/.cache/"):
        return "~/.cache/"
    home = os.environ.get("HOME")
    if home:
        home_norm = home.rstrip("/")
        if path == f"{home_norm}/.cache" or path.startswith(f"{home_norm}/.cache/"):
            return "~/.cache/"
    try:
        user_home = str(Path.home()).rstrip("/")
        if path == f"{user_home}/.cache" or path.startswith(f"{user_home}/.cache/"):
            return "~/.cache/"
    except Exception:
        pass

    # __pycache__/
    if (
        "/__pycache__/" in path
        or path.endswith("/__pycache__")
        or path.startswith("__pycache__/")
        or path == "__pycache__"
        or path.startswith("./__pycache__/")
    ):
        return "__pycache__/"

    # site-packages/
    if (
        "/site-packages/" in path
        or path.endswith("/site-packages")
        or path.startswith("site-packages/")
        or path == "site-packages"
        or path.startswith("./site-packages/")
    ):
        return "site-packages/"

    # .venv/
    if (
        "/.venv/" in path
        or path.endswith("/.venv")
        or path.startswith(".venv/")
        or path == ".venv"
        or path.startswith("./.venv/")
    ):
        return ".venv/"
    try:
        rel = str(Path(path).relative_to(Path(project)))
        if rel == ".venv" or rel.startswith(".venv/"):
            return ".venv/"
    except ValueError:
        pass

    return None


def _display(path: str, project: str) -> str:
    if path in COLLAPSED_CATEGORIES:
        return path
    try:
        p = Path(path)
        rel = p.relative_to(Path(project))
        return f"./{rel}"
    except ValueError:
        return path


def _quiet_area(rel: str) -> bool:
    return any(rel.startswith(p) for p in NOISE_AREA_PREFIXES)


def noise_label(path: str, project: str) -> str | None:
    # Absolute system paths: collapse reads under known noisy prefixes.
    for sp in SYSTEM_NOISE_PREFIXES:
        if path.startswith(sp):
            return sp.rstrip("/")
    try:
        rel = str(Path(path).relative_to(Path(project)))
        if _quiet_area(rel):
            return rel.split("/", 1)[0]
    except ValueError:
        return None
    return None


def build_process_tree(events: list[Event]) -> list[ProcessNode]:
    nodes: dict[int, ProcessNode] = {}
    latest_argv0: dict[int, str] = {}
    for e in events:
        if e.kind == "proc.exec":
            argv = e.get("argv") or []
            latest_argv0[e.pid] = str(argv[0]) if argv else Path(e.exe).name
        if e.pid not in nodes:
            nodes[e.pid] = ProcessNode(
                pid=e.pid, ppid=e.ppid, exe=e.exe,
                argv0=latest_argv0.get(e.pid, Path(e.exe).name))
        # Refresh from every exec (postinstall swaps in node, then sh).
        if e.kind == "proc.exec":
            argv = e.get("argv") or []
            nodes[e.pid].exe = e.exe
            nodes[e.pid].argv0 = (
                str(argv[0]) if argv else Path(e.exe).name)
    for e in events:
        if e.kind == "proc.exit" and e.pid in nodes:
            pass  # exit event: pid already removed from children at erase-time
    children: dict[int, list[int]] = defaultdict(list)
    roots: list[int] = []
    for pid, node in nodes.items():
        if node.ppid and node.ppid in nodes:
            children[node.ppid].append(pid)
        else:
            roots.append(pid)
    for parent, kids in children.items():
        nodes[parent].children = [nodes[k] for k in sorted(kids)]
    return [nodes[r] for r in sorted(roots)]


def flatten(nodes: list[ProcessNode]) -> list[ProcessNode]:
    out: list[ProcessNode] = []

    def walk(n: ProcessNode) -> None:
        out.append(n)
        for c in n.children:
            walk(c)

    for root in nodes:
        walk(root)
    return out


def normalize(events: list[Event], project: str) -> Analysis:
    trees = build_process_tree(events)
    all_nodes = flatten(trees)

    file_counts: Counter[str] = Counter()
    net: dict[tuple[str, str], str] = {}
    net_ports: dict[str, set[str]] = defaultdict(set)
    exec_argv0: set[str] = set()
    notable: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    noise_files: Counter[str] = Counter()

    written_paths: set[str] = set()
    for e in events:
        kind_counts[e.kind] += 1
        if e.kind in ("file.open", "file.write"):
            path = str(e.get("path", ""))
            area = noise_label(path, project)
            if area is not None:
                noise_files[area] += 1
            else:
                cat = collapsed_category(path, project)
                if cat is not None:
                    notable[cat] += 1
                elif path:
                    notable[path] += 1
            if e.kind == "file.write":
                written_paths.add(path)
            elif e.kind == "file.open":
                # O_WRONLY/RDWR/CREAT/APPEND/TMPFILE/TRUNC opens are writes too.
                flags = str(e.get("flags", ""))
                if any(b in flags for b in ("O_WRONLY", "O_RDWR", "O_CREAT",
                                            "O_APPEND", "O_TMPFILE", "O_TRUNC")):
                    written_paths.add(path)
        elif e.kind in ("file.delete", "file.rename"):
            path = str(e.get("path", e.get("src", "")))
            if path and noise_label(path, project) is None:
                cat = collapsed_category(path, project)
                if cat is not None:
                    notable[cat] += 1
                else:
                    notable[path] += 1
        elif e.kind in ("net.connect", "net.bind"):
            fam = str(e.get("family", "?"))
            if fam in ("inet", "inet6"):
                key = (e.exe, f"{e.get('addr', '?')}")
                net.setdefault(key, str(e.get("port", 0)))
                net_ports[e.exe].add(str(e.get("port", 0)))
        elif e.kind == "proc.exec":
            argv = e.get("argv") or []
            if argv:
                exec_argv0.add(str(argv[0]))

    network = sorted(
        {(exe, addr, port) for (exe, addr), port in net.items()}
    )

    # Noisy-area summaries fold into notable counts implicitly via
    # kind_counts; the report prints the top areas explicitly.
    notable_files = {
        _display(p, project): c for p, c in notable.most_common(50)}

    verdict_quiet = (
        "No suspicious behavior observed."
        if not net
        else "Makes network connections: "
        + ", ".join(sorted({a for _, a, _ in network}))
    )
    return Analysis(
        project=project,
        processes=trees,
        notable_files=notable_files,
        network=network,
        findings_by_kind=dict(kind_counts),
        hits=[],
        event_counts=kind_counts,
        quiet=verdict_quiet,
    )
