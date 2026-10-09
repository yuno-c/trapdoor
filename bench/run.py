#!/usr/bin/env python3
"""Trapdoor benchmark suite (Milestone 4).

Measures runtime and memory overhead of Trapdoor across best-case, worst-case,
and realistic package-installation workloads under multiple conditions.

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "bench"
CACHE_DIR = BENCH_DIR / ".cache"
RESULTS_DIR = BENCH_DIR / "results"

TMPFS_DIR = Path("/dev/shm") if Path("/dev/shm").is_dir() and os.access("/dev/shm", os.W_OK) else Path(tempfile.gettempdir())


def get_watched_syscalls() -> list[str]:
    """Parse watched syscalls dynamically from tracer/src/seccomp.cpp."""
    seccomp_cpp = REPO_ROOT / "tracer" / "src" / "seccomp.cpp"
    if not seccomp_cpp.is_file():
        raise FileNotFoundError(f"Missing {seccomp_cpp}")
    text = seccomp_cpp.read_text()
    syscalls = re.findall(r'maybe_add\s*\(\s*out\s*,\s*__NR_(\w+)\s*\)', text)
    if not syscalls:
        raise RuntimeError(f"Could not extract watched syscalls from {seccomp_cpp}")
    return syscalls


def _read_file_safe(p: str | Path) -> str:
    try:
        return Path(p).read_text().strip()
    except Exception:
        return "unknown"


def get_environment_info() -> dict:
    """Collect hardware, OS, and tool environment metadata without private info."""
    cpu_model = "unknown"
    try:
        for line in _read_file_safe("/proc/cpuinfo").splitlines():
            if "model name" in line:
                cpu_model = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass

    governor = "unknown"
    for p in (
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor",
    ):
        v = _read_file_safe(p)
        if v != "unknown":
            governor = v
            break

    epp = "unknown"
    for p in (
        "/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference",
        "/sys/devices/system/cpu/cpufreq/policy0/energy_performance_preference",
    ):
        v = _read_file_safe(p)
        if v != "unknown":
            epp = v
            break

    power_states: list[str] = []
    for ps in glob.glob("/sys/class/power_supply/*"):
        name = os.path.basename(ps)
        t = _read_file_safe(os.path.join(ps, "type"))
        s = _read_file_safe(os.path.join(ps, "status"))
        online = _read_file_safe(os.path.join(ps, "online"))
        power_states.append(f"{name} ({t}): status={s}, online={online}")

    os_release = "Linux"
    if os.path.isfile("/etc/os-release"):
        for line in _read_file_safe("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                os_release = line.split("=", 1)[1].strip('"\'')
                break

    def _tool_version(cmd: list[str]) -> str:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.stdout.splitlines()[0].strip()
        except Exception:
            return "not found"

    power_profile = _tool_version(["powerprofilesctl", "get"])

    tools = {
        "python": sys.version.split()[0],
        "gcc": _tool_version(["gcc", "--version"]),
        "cmake": _tool_version(["cmake", "--version"]),
        "node": _tool_version(["node", "--version"]),
        "npm": _tool_version(["npm", "--version"]),
        "pip": _tool_version(["pip", "--version"]),
        "strace": _tool_version(["strace", "--version"]),
        "docker": _tool_version(["docker", "--version"]),
    }

    try:
        load_avg = list(os.getloadavg())
    except Exception:
        load_avg = []

    return {
        "cpu_model": cpu_model,
        "cpu_logical_cores": os.cpu_count(),
        "cpu_governor": governor,
        "energy_performance_preference": epp,
        "power_profile": power_profile,
        "power_state": "; ".join(power_states) if power_states else "unknown",
        "kernel": os.uname().release,
        "os": os_release,
        "load_avg_1m": load_avg[0] if load_avg else None,
        "tools": tools,
    }


def get_docker_daemon_rss_kb() -> int | None:
    """Query resident memory of dockerd and containerd in kilobytes."""
    try:
        res = subprocess.run(
            ["ps", "-C", "dockerd,containerd", "-o", "rss="],
            capture_output=True, text=True, check=True
        )
        total_kb = sum(int(line.strip()) for line in res.stdout.splitlines() if line.strip())
        return total_kb if total_kb > 0 else None
    except Exception:
        return None


def is_docker_available(image: str) -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            return False
        res = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def find_tracer_bin() -> Path:
    for cand in (
        REPO_ROOT / "build" / "tracer" / "trapdoor-trace",
        REPO_ROOT / "build" / "trapdoor-trace",
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    found = shutil.which("trapdoor-trace")
    if found:
        return Path(found)
    raise FileNotFoundError(
        "trapdoor-trace not found. Run 'cmake -S . -B build && cmake --build build -j'."
    )


def setup_workloads():
    """Prepare pre-warmed offline wheelhouse and npm cache in bench/.cache/."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    wheelhouse = CACHE_DIR / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)

    print(f"[*] Setting up pip offline wheelhouse in {wheelhouse}...")
    shm_wh = Path("/dev/shm/test_wheelhouse")
    if shm_wh.is_dir():
        for whl in shm_wh.glob("*.whl"):
            dest_whl = wheelhouse / whl.name
            if not dest_whl.is_file():
                shutil.copy2(whl, dest_whl)

    wheels = list(wheelhouse.glob("*.whl"))
    if not wheels or not any("rich" in w.name for w in wheels):
        pip_bin = shutil.which("pip") or "pip"
        cmd = [pip_bin, "download", "--dest", str(wheelhouse),
               "--only-binary=:all:", "rich"]
        res = subprocess.run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to download wheels for pip benchmark: exit code {res.returncode}")
    print(f"    Wheelhouse contains {len(list(wheelhouse.glob('*.whl')))} wheels.")

    npm_project = CACHE_DIR / "npm_project"
    npm_cache = CACHE_DIR / "npm_cache"
    npm_project.mkdir(parents=True, exist_ok=True)
    npm_cache.mkdir(parents=True, exist_ok=True)

    print(f"[*] Setting up npm offline cache and fixture in {npm_project}...")
    pkg_json = npm_project / "package.json"
    if not pkg_json.is_file():
        pkg_json.write_text(json.dumps({
            "name": "bench-npm",
            "version": "1.0.0",
            "dependencies": {
                "is-number": "^7.0.0"
            }
        }, indent=2))

    lock_file = npm_project / "package-lock.json"
    if not lock_file.is_file():
        res = subprocess.run(
            ["npm", "install", "--cache", str(npm_cache), "--no-audit", "--no-fund"],
            cwd=str(npm_project)
        )
        if res.returncode != 0:
            raise RuntimeError(f"Failed to prime npm cache: exit code {res.returncode}")
        shutil.rmtree(npm_project / "node_modules", ignore_errors=True)
    print("    npm fixture and cache ready.")


def run_command(
    cmd: list[str],
    cwd: str | Path | None = None,
    env: dict | None = None
) -> tuple[float, int, int, int | None]:
    """Execute a command, returning (elapsed_seconds, exit_code, target_maxrss_kb, tracer_peak_rss_kb).

    Uses os.wait4 to obtain the target process's peak resident memory (ru_maxrss).
    Parses 'trapdoor-trace-stats: peak_rss_kb=<N>' from stderr if emitted.
    """
    pipe_r, pipe_w = os.pipe()

    t0 = time.monotonic()
    pid = os.fork()
    if pid == 0:
        os.close(pipe_r)
        os.dup2(pipe_w, 2)  # redirect stderr to pipe
        os.close(pipe_w)
        # redirect stdout to /dev/null
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.close(devnull)
        if cwd:
            os.chdir(cwd)
        os.execvpe(cmd[0], cmd, env if env is not None else os.environ)

    os.close(pipe_w)
    stderr_bytes = bytearray()
    while True:
        chunk = os.read(pipe_r, 4096)
        if not chunk:
            break
        stderr_bytes.extend(chunk)
    os.close(pipe_r)

    _, status, rusage = os.wait4(pid, 0)
    t1 = time.monotonic()
    elapsed = t1 - t0

    exit_code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
    target_maxrss_kb = rusage.ru_maxrss

    stderr_str = stderr_bytes.decode("utf-8", errors="replace")
    tracer_rss_kb: int | None = None
    m = re.search(r"trapdoor-trace-stats:\s*peak_rss_kb=(\d+)", stderr_str)
    if m:
        tracer_rss_kb = int(m.group(1))

    if exit_code != 0:
        raise RuntimeError(
            f"Command failed with exit code {exit_code}:\n"
            f"Command: {' '.join(cmd)}\n"
            f"Stderr:\n{stderr_str}"
        )

    return elapsed, exit_code, target_maxrss_kb, tracer_rss_kb


class Workload:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def prepare(self):
        pass

    def cleanup(self):
        pass

    def get_command(self, condition: str, tracer_bin: Path, syscalls: list[str],
                    event_path: Path, docker_image: str) -> tuple[list[str], str | Path | None, dict | None]:
        raise NotImplementedError


class CpuWorkload(Workload):
    def __init__(self):
        super().__init__("cpu", "CPU-bound SHA-256 computation (1-2s)")

    def get_command(self, condition: str, tracer_bin: Path, syscalls: list[str],
                    event_path: Path, docker_image: str) -> tuple[list[str], str | Path | None, dict | None]:
        target = [sys.executable, "-c", "import hashlib; [hashlib.sha256(b'x'*1024).digest() for _ in range(1_500_000)]"]
        env = dict(os.environ)

        if condition == "bare":
            return target, None, env
        elif condition == "trace":
            return [str(tracer_bin), "--stats", "-o", str(event_path), "--", *target], None, env
        elif condition == "full":
            env["TRAPDOOR_TRACE_STATS"] = "1"
            env["PYTHONPATH"] = str(REPO_ROOT / "src") + (os.pathsep + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else "")
            return [sys.executable, "-m", "trapdoor.cli", "run", "-o", str(event_path), "--", *target], None, env
        elif condition == "strace":
            return ["strace", "-f", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], None, env
        elif condition == "strace-seccomp":
            return ["strace", "-f", "--seccomp-bpf", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], None, env
        elif condition == "docker":
            return ["docker", "run", "--rm", "python:3.13-slim", "python3", "-c", "import hashlib; [hashlib.sha256(b'x'*1024).digest() for _ in range(1_500_000)]"], None, env
        raise ValueError(condition)


class FileWorkload(Workload):
    def __init__(self):
        super().__init__("file", "File-heavy I/O (2,500 file create/write/rename/delete on tmpfs)")
        self.tmp_work_dir = TMPFS_DIR / "trapdoor-bench-file-workdir"

    def prepare(self):
        shutil.rmtree(self.tmp_work_dir, ignore_errors=True)
        self.tmp_work_dir.mkdir(parents=True, exist_ok=True)

    def cleanup(self):
        shutil.rmtree(self.tmp_work_dir, ignore_errors=True)

    def get_command(self, condition: str, tracer_bin: Path, syscalls: list[str],
                    event_path: Path, docker_image: str) -> tuple[list[str], str | Path | None, dict | None]:
        script = (
            f"import os\n"
            f"d = '{self.tmp_work_dir}'\n"
            f"for i in range(2500):\n"
            f"    p = os.path.join(d, f'f_{{i}}.txt')\n"
            f"    with open(p, 'w') as f: f.write('benchmark-payload')\n"
            f"    p2 = os.path.join(d, f'ren_{{i}}.txt')\n"
            f"    os.rename(p, p2)\n"
            f"    os.unlink(p2)\n"
        )
        target = [sys.executable, "-c", script]
        env = dict(os.environ)

        if condition == "bare":
            return target, None, env
        elif condition == "trace":
            return [str(tracer_bin), "--stats", "-o", str(event_path), "--", *target], None, env
        elif condition == "full":
            env["TRAPDOOR_TRACE_STATS"] = "1"
            env["PYTHONPATH"] = str(REPO_ROOT / "src") + (os.pathsep + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else "")
            return [sys.executable, "-m", "trapdoor.cli", "run", "-o", str(event_path), "--", *target], None, env
        elif condition == "strace":
            return ["strace", "-f", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], None, env
        elif condition == "strace-seccomp":
            return ["strace", "-f", "--seccomp-bpf", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], None, env
        elif condition == "docker":
            return ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{self.tmp_work_dir}:{self.tmp_work_dir}", "python:3.13-slim", "python3", "-c", script], None, env
        raise ValueError(condition)


class PipWorkload(Workload):
    def __init__(self):
        super().__init__("pip", "Offline pip install from local wheelhouse")
        self.wheelhouse = CACHE_DIR / "wheelhouse"
        self.scratch_target = TMPFS_DIR / "trapdoor-bench-pip-target"

    def prepare(self):
        shutil.rmtree(self.scratch_target, ignore_errors=True)
        self.scratch_target.mkdir(parents=True, exist_ok=True)

    def cleanup(self):
        shutil.rmtree(self.scratch_target, ignore_errors=True)

    def get_command(self, condition: str, tracer_bin: Path, syscalls: list[str],
                    event_path: Path, docker_image: str) -> tuple[list[str], str | Path | None, dict | None]:
        pip_bin = shutil.which("pip") or "pip"
        target = [
            pip_bin, "install",
            "--no-index", "--find-links", str(self.wheelhouse),
            "--target", str(self.scratch_target),
            "rich", "--isolated", "--no-input"
        ]
        env = dict(os.environ)

        if condition == "bare":
            return target, None, env
        elif condition == "trace":
            return [str(tracer_bin), "--stats", "-o", str(event_path), "--", *target], None, env
        elif condition == "full":
            env["TRAPDOOR_TRACE_STATS"] = "1"
            env["PYTHONPATH"] = str(REPO_ROOT / "src") + (os.pathsep + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else "")
            return [sys.executable, "-m", "trapdoor.cli", "run", "-o", str(event_path), "--", *target], None, env
        elif condition == "strace":
            return ["strace", "-f", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], None, env
        elif condition == "strace-seccomp":
            return ["strace", "-f", "--seccomp-bpf", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], None, env
        elif condition == "docker":
            return [
                "docker", "run", "--rm",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{self.wheelhouse}:{self.wheelhouse}",
                "-v", f"{self.scratch_target}:{self.scratch_target}",
                "python:3.13-slim", "pip", "install",
                "--no-index", "--find-links", str(self.wheelhouse),
                "--target", str(self.scratch_target),
                "rich", "--isolated", "--no-input"
            ], None, env
        raise ValueError(condition)


class NpmWorkload(Workload):
    def __init__(self):
        super().__init__("npm", "Offline npm ci from pre-warmed cache")
        self.project_dir = CACHE_DIR / "npm_project"
        self.cache_dir = CACHE_DIR / "npm_cache"

    def prepare(self):
        shutil.rmtree(self.project_dir / "node_modules", ignore_errors=True)

    def cleanup(self):
        shutil.rmtree(self.project_dir / "node_modules", ignore_errors=True)

    def get_command(self, condition: str, tracer_bin: Path, syscalls: list[str],
                    event_path: Path, docker_image: str) -> tuple[list[str], str | Path | None, dict | None]:
        target = ["npm", "ci", "--offline", "--cache", str(self.cache_dir), "--no-audit", "--no-fund", "--loglevel=error"]
        env = dict(os.environ)

        if condition == "bare":
            return target, self.project_dir, env
        elif condition == "trace":
            return [str(tracer_bin), "--stats", "-o", str(event_path), "--", *target], self.project_dir, env
        elif condition == "full":
            env["TRAPDOOR_TRACE_STATS"] = "1"
            env["PYTHONPATH"] = str(REPO_ROOT / "src") + (os.pathsep + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else "")
            return [sys.executable, "-m", "trapdoor.cli", "run", "-o", str(event_path), "--", *target], self.project_dir, env
        elif condition == "strace":
            return ["strace", "-f", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], self.project_dir, env
        elif condition == "strace-seccomp":
            return ["strace", "-f", "--seccomp-bpf", f"-e", f"trace={','.join(syscalls)}", "-o", "/dev/null", "--", *target], self.project_dir, env
        elif condition == "docker":
            return [
                "docker", "run", "--rm",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{self.project_dir}:{self.project_dir}",
                "-v", f"{self.cache_dir}:{self.cache_dir}",
                "-w", str(self.project_dir),
                "--entrypoint", "npm",
                "mcr.microsoft.com/devcontainers/javascript-node:4-24", "ci", "--offline",
                "--cache", str(self.cache_dir), "--no-audit", "--no-fund", "--loglevel=error"
            ], None, env
        raise ValueError(condition)


def calc_stats(values: list[float]) -> dict:
    if not values:
        return {}
    s = sorted(values)
    n = len(s)
    med = statistics.median(s)
    v_min = s[0]
    v_max = s[-1]
    if n >= 4:
        q1, _, q3 = statistics.quantiles(s, n=4)
        iqr = q3 - q1
    else:
        q1 = v_min
        q3 = v_max
        iqr = q3 - q1
    return {
        "median": med,
        "min": v_min,
        "max": v_max,
        "iqr": iqr,
        "count": n,
    }


def run_benchmark(
    runs: int,
    warmup: int,
    include_docker: bool,
    smoke: bool,
    output_path: Path | None = None
) -> dict:
    setup_workloads()
    tracer_bin = find_tracer_bin()
    syscalls = get_watched_syscalls()
    docker_image = "mcr.microsoft.com/devcontainers/javascript-node:4-24"

    conditions = ["bare", "trace", "full", "strace", "strace-seccomp"]
    docker_available = include_docker and is_docker_available(docker_image)
    if docker_available:
        conditions.append("docker")
    elif include_docker:
        print("[!] Docker condition requested but Docker daemon or image is unavailable. Skipping 'docker'.")

    workloads: list[Workload] = [
        CpuWorkload(),
        FileWorkload(),
        PipWorkload(),
        NpmWorkload(),
    ]

    print(f"[*] Starting Trapdoor benchmark:")
    print(f"    Conditions: {', '.join(conditions)}")
    print(f"    Workloads: {', '.join(w.name for w in workloads)}")
    print(f"    Iterations: {runs} (warmup: {warmup})")
    print(f"    Tmpfs path: {TMPFS_DIR}")
    print(f"    Tracer binary: {tracer_bin}")

    env_info = get_environment_info()
    docker_daemon_rss = get_docker_daemon_rss_kb() if docker_available else None

    # Collect raw metrics: results[workload.name][condition] = { "times": [...], "target_rss": [...], "tracer_rss": [...], "events": [...] }
    results: dict[str, dict[str, dict[str, list]]] = {}

    for w in workloads:
        results[w.name] = {}
        for c in conditions:
            results[w.name][c] = {
                "times": [],
                "target_rss": [],
                "tracer_rss": [],
                "events": [],
            }

        print(f"\n[+] Running workload: {w.name} ({w.description})")

        # Warmup runs
        for w_idx in range(warmup):
            for c in conditions:
                w.prepare()
                event_file = TMPFS_DIR / f"bench-events-warmup-{os.getpid()}.jsonl"
                cmd, cwd, env = w.get_command(c, tracer_bin, syscalls, event_file, docker_image)
                try:
                    run_command(cmd, cwd=cwd, env=env)
                finally:
                    if event_file.is_file():
                        event_file.unlink()
                    w.cleanup()

        # Timed runs with interleaved / alternating order
        for round_idx in range(runs):
            round_conds = list(conditions) if (round_idx % 2 == 0) else list(reversed(conditions))
            for c in round_conds:
                w.prepare()
                event_file = TMPFS_DIR / f"bench-events-{w.name}-{c}-{round_idx}-{os.getpid()}.jsonl"
                cmd, cwd, env = w.get_command(c, tracer_bin, syscalls, event_file, docker_image)
                try:
                    elapsed, rc, target_rss, tracer_rss = run_command(cmd, cwd=cwd, env=env)

                    events_count = 0
                    if c in ("trace", "full"):
                        if not event_file.is_file():
                            raise RuntimeError(f"Event file {event_file} was not created for {c} run!")
                        lines = [l for l in event_file.read_text().splitlines() if l.strip()]
                        events_count = len(lines)
                        if events_count == 0:
                            raise RuntimeError(f"Zero events captured in {c} run for {w.name}!")

                    results[w.name][c]["times"].append(elapsed)
                    results[w.name][c]["target_rss"].append(target_rss)
                    if tracer_rss is not None:
                        results[w.name][c]["tracer_rss"].append(tracer_rss)
                    if c in ("trace", "full"):
                        results[w.name][c]["events"].append(events_count)
                finally:
                    if event_file.is_file():
                        event_file.unlink()
                    w.cleanup()
            print(f"    Completed iteration {round_idx + 1}/{runs} across all conditions.")

    # Compute summary statistics
    summary: dict[str, dict[str, dict]] = {}
    for w_name, cond_data in results.items():
        summary[w_name] = {}
        bare_median = statistics.median(cond_data["bare"]["times"]) if cond_data.get("bare") else 1.0

        for c, data in cond_data.items():
            t_stats = calc_stats(data["times"])
            ratio = t_stats["median"] / bare_median if bare_median > 0 else 1.0
            delta_ms = (t_stats["median"] - bare_median) * 1000.0

            target_rss_stats = calc_stats(data["target_rss"])
            tracer_rss_stats = calc_stats(data["tracer_rss"]) if data["tracer_rss"] else None
            events_stats = calc_stats(data["events"]) if data["events"] else None

            summary[w_name][c] = {
                "time": t_stats,
                "overhead_ratio": ratio,
                "overhead_delta_ms": delta_ms,
                "target_rss_kb": target_rss_stats,
                "tracer_rss_kb": tracer_rss_stats,
                "events": events_stats,
            }

    # Print markdown table
    print("\n" + "=" * 80)
    print("BENCHMARK RESULTS SUMMARY")
    print("=" * 80)

    header = "| Workload | Condition | Median (s) | Min (s) | Max (s) | IQR (s) | Overhead Ratio | Overhead Delta | Target Peak RSS | Tracer Peak RSS |"
    sep = "|---|---|---|---|---|---|---|---|---|---|"
    print(header)
    print(sep)

    condition_labels = {
        "bare": "bare",
        "trace": "trapdoor-trace",
        "full": "trapdoor run",
        "strace": "strace -f",
        "strace-seccomp": "strace -f --seccomp-bpf",
        "docker": "docker (isolation)",
    }

    for w_name, conds in summary.items():
        for c, s in conds.items():
            t = s["time"]
            ratio_str = f"{s['overhead_ratio']:.2f}x"
            delta_str = f"{s['overhead_delta_ms']:+.1f} ms" if c != "bare" else "baseline"
            target_rss_str = f"{s['target_rss_kb']['median'] / 1024:.1f} MB"
            tracer_rss_str = (
                f"{s['tracer_rss_kb']['median'] / 1024:.1f} MB" if s["tracer_rss_kb"] else (
                    f"daemon ~{docker_daemon_rss / 1024:.0f} MB" if (c == "docker" and docker_daemon_rss) else "n/a"
                )
            )
            print(
                f"| {w_name} | {condition_labels.get(c, c)} | {t['median']:.3f} | {t['min']:.3f} | {t['max']:.3f} | {t['iqr']:.3f} | {ratio_str} | {delta_str} | {target_rss_str} | {tracer_rss_str} |"
            )

    print("\nCaveats & Notes:")
    print("1. All workloads run strictly offline with local caches to prevent network jitter.")
    print("2. 'trace' is trapdoor-trace C++ engine alone; 'full' includes Python analysis and report rendering.")
    print("3. Memory is defined as largest single process peak resident memory (ru_maxrss).")
    print("4. Docker condition measures container execution; Docker daemon footprint (~50-100MB resident) is reported separately.")

    # Save to JSON
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = RESULTS_DIR / f"bench_{ts}.json"

    final_payload = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "config": {
            "runs": runs,
            "warmup": warmup,
            "smoke": smoke,
            "conditions": conditions,
            "watched_syscalls": syscalls,
            "docker_image": docker_image if docker_available else None,
            "docker_daemon_rss_kb": docker_daemon_rss,
        },
        "environment": env_info,
        "summary": summary,
        "raw_results": results,
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(final_payload, f, indent=2)
    print(f"\n[+] Raw results saved to: {output_path}")

    return final_payload


def main():
    parser = argparse.ArgumentParser(description="Run Trapdoor benchmarks (M4)")
    parser.add_argument("--setup", action="store_true", help="Prepare offline wheelhouse and npm cache without running benchmarks")
    parser.add_argument("--smoke", action="store_true", help="Smoke mode: run 1 iteration of each workload and condition to verify correctness")
    parser.add_argument("--runs", type=int, default=30, help="Number of timed iterations per condition (default: 30)")
    parser.add_argument("--warmup", type=int, default=2, help="Number of warmup iterations (default: 2)")
    parser.add_argument("--no-docker", action="store_true", help="Skip the Docker condition even if Docker is available")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Path to save output JSON")
    args = parser.parse_args()

    if args.setup:
        setup_workloads()
        print("[+] Setup completed successfully.")
        return 0

    runs = 1 if args.smoke else args.runs
    warmup = 1 if args.smoke else args.warmup

    run_benchmark(
        runs=runs,
        warmup=warmup,
        include_docker=not args.no_docker,
        smoke=args.smoke,
        output_path=args.output
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
