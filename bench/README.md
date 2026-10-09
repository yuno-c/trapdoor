# Trapdoor Benchmark Methodology

This document defines the methodology for measuring, evaluating, and publishing the runtime and memory overhead of Trapdoor (Milestone 4).

The goal is **honest, reproducible measurement**. Trapdoor observes syscalls via `seccomp-bpf` and `ptrace`. We measure and report overhead across best-case, worst-case, and realistic package-installation workloads. We do **not** optimize the tracer in this milestone; any identified performance bottlenecks are recorded as notes for future work.

Every claim in the project documentation and README must be backed by a concrete number from this benchmark suite. If overhead is high under certain workloads, we state it plainly.

---

## 1. Conditions Compared

Every workload is evaluated under the following conditions:

1. **Bare Command (`bare`)**  
   The target workload runs directly on the host system without any wrapper, tracing, or containerization. This establishes the baseline execution time and baseline peak memory.

2. **Tracer Alone (`trace`)**  
   The target command runs under the C++ binary `trapdoor-trace` alone, writing events to a file on tmpfs (e.g. `/dev/shm`), with no Python analysis.  
   This isolates the kernel-level interception cost: `seccomp-bpf` filtering, `ptrace` stop/continue context switches, tracee memory reads (`process_vm_readv`), path resolution (`/proc/<pid>/cwd`, `/proc/<pid>/fd/`), and JSON Lines serialization.

3. **Full Trapdoor Run (`full`)**  
   The target command runs via the full CLI (`trapdoor run -o <tmpfs_path> -- <cmd>`).  
   This measures the complete user-facing tool pipeline: C++ tracing, JSON event ingestion, process tree reconstruction, noise collapsing, declarative rules engine evaluation (`rules.toml`), and human/JSON report generation.

4. **Filtered strace (`strace`)**  
   The target command runs under classic `strace -f` filtered to the exact watched syscalls:
   ```sh
   strace -f -e trace=<syscalls> -o /dev/null -- <cmd>
   ```
   The syscall filter list is generated dynamically from the tracer's source (`tracer/src/seccomp.cpp`) rather than typed manually. This represents the classic "raw ptrace" alternative without seccomp-bpf acceleration.

5. **Filtered strace with seccomp-bpf (`strace-seccomp`)**  
   The target command runs under `strace -f --seccomp-bpf` with the identical dynamically generated syscall filter:
   ```sh
   strace -f --seccomp-bpf -e trace=<syscalls> -o /dev/null -- <cmd>
   ```
   This isolates how general-purpose `strace` performs when kernel-level seccomp-bpf acceleration is enabled, providing a direct comparison against Trapdoor's purpose-built tracer.

6. **Docker Container (`docker`) — Isolation vs. Observation (Optional / Conditional)**  
   The target command runs inside a pre-pulled, lightweight container image (`docker run --rm ...`).  
   This evaluates the "container isolation" approach frequently used instead of in-place behavioral observation.  
   *Conditionality*: If Docker is not installed or the Docker daemon is unreachable, this condition is cleanly skipped with an explicit note in the report. When measured, memory reporting includes the resident memory of the Docker daemon (`dockerd` / `containerd`), not merely the container's isolated RSS.

---

## 2. Workloads

All benchmark workloads are **fully offline and deterministic**. Network access is disabled or unreferenced so network latency, CDN packet loss, and DNS jitter cannot swamp or disguise tool overhead.

Scratch directories, target virtual environments, and `node_modules` trees are freshly cleaned between runs. Output event streams are written to tmpfs (such as `/dev/shm`) so disk I/O differences do not pollute timing.

### Workload 1: CPU-Bound (Best Case)
- **Description**: Pure in-memory computation with minimal system calls, scaled to run for at least 1–2 seconds.
- **Implementation**: A Python script computing SHA-256 digests over in-memory blocks in a tight loop:
  ```sh
  python3 -c "import hashlib; [hashlib.sha256(b'x'*1024).digest() for _ in range(1_500_000)]"
  ```
- **Rationale**: Demonstrates the theoretical best case. Because `seccomp-bpf` allows non-watched syscalls and compute instructions to execute at native speed, the tracer is rarely or never woken. Overhead should approach 0%.

### Workload 2: File-Heavy / I/O-Bound (Worst Case)
- **Description**: Rapid creation, inspection, renaming, and deletion of thousands of small files across a directory tree.
- **Implementation**: A deterministic script creating 2,500 files in a temporary tree, opening and writing data to them, renaming them, and unlinking them (over 10,000 watched syscalls).
- **Rationale**: Demonstrates the theoretical worst case. Every file operation invokes a watched syscall (`openat`, `renameat`, `unlinkat`), triggering a seccomp trap, a `ptrace` context switch to the tracer, register and memory reads, and JSON serialization. This stresses the tracer's interception path and exposes the upper bound of Trapdoor's runtime overhead.

### Workload 3: Real Python Package Install (`pip`)
- **Description**: Realistic Python dependency installation from a pre-warmed, local wheelhouse without network access.
- **Implementation**:
  ```sh
  pip install --no-index --find-links <wheelhouse> --target <scratch_dir> rich
  ```
- **Setup**: A setup script populates `<wheelhouse>` once beforehand with all `.whl` files (and their dependencies) downloaded from PyPI. The benchmark runs strictly offline with `--no-index`.
- **Rationale**: Real-world workflow with realistic file writes, metadata queries, and bytecode compilation.

### Workload 4: Real Node Package Install (`npm`)
- **Description**: Realistic JavaScript package installation from a warmed offline cache.
- **Implementation**:
  ```sh
  npm ci --offline --cache <npm_cache>
  ```
  executed inside a fixture directory containing a pinned `package.json` and `package-lock.json`.
- **Setup**: A setup script populates `<npm_cache>` beforehand. The benchmark runs strictly offline, deleting `node_modules` before each iteration.
- **Rationale**: Real-world workflow involving deep directory hierarchies, rapid unarchiving, symlink creation, and multi-process spawns (`npm` -> `node` child workers).

### Setup Script Hygiene
- The wheelhouse and npm cache directories are generated on-demand by `bench/run.py --setup` and stored in untracked local directories (`bench/.cache/`).
- Cached wheel files, tarballs, and generated scratch directories are gitignored and **never** committed to the repository.

---

## 3. Statistical Rigor

To ensure data integrity and avoid transient host interference:

1. **Warmup Runs**:
   - For every workload and condition, 1–2 warmup runs are executed and discarded prior to measurement.
   - This ensures disk caches, dynamic linker lookups, Python bytecode caches, and shared library pages are primed.

2. **Sample Size**:
   - At least **30 timed iterations** ($N \ge 30$) are collected for each condition.

3. **Alternating / Interleaved Execution Order**:
   - Benchmarks are **not** run in batched blocks (e.g. running 30 bare runs, then 30 trace runs). Batched execution is vulnerable to thermal throttling, CPU frequency scaling, or background system drift.
   - Runs are interleaved in round-robin order across conditions:
     - Round 1: `bare` -> `trace` -> `full` -> `strace` -> `strace-seccomp` -> `docker`
     - Round 2: `docker` -> `strace-seccomp` -> `strace` -> `full` -> `trace` -> `bare`
     - ...

4. **Correctness Assertions & Fail-Loud Checks**:
   - Every single run must exit with return code 0. If any command exits non-zero, the benchmark aborts loudly immediately.
   - For `trace` and `full` conditions, the runner verifies that non-zero events were captured in the event stream. Zero events indicate an interception failure and trigger an immediate hard abort.

5. **Metrics Reported**:
   - **Median**: Primary summary metric (robust against outliers).
   - **Min**: Cleanest execution run with minimum scheduling jitter.
   - **Max**: Worst recorded run during the benchmark.
   - **IQR (Interquartile Range)**: $Q_{75} - Q_{25}$, quantifying distribution spread and measurement stability.
   - **Overhead**: Reported both as:
     - **Ratio**: $\text{median}_{\text{condition}} / \text{median}_{\text{bare}}$ (e.g., $1.25\times$)
     - **Absolute Difference**: $\text{median}_{\text{condition}} - \text{median}_{\text{bare}}$ (e.g., $+180\text{ ms}$)

---

## 4. Memory Footprint Measurement

"No daemon, no VM" is a primary claim regarding Trapdoor's operational footprint. Conflating target process memory with tracer memory obscures the tool's actual cost. Memory is measured and reported with strict separation:

1. **Definition of Memory**:
   - Memory is defined as the largest single process peak resident set size (`ru_maxrss`).

2. **Target Peak RSS**:
   - Peak resident set size of the target process tree alone.

3. **Tracer Peak RSS**:
   - Peak resident set size of the tracer process itself (`trapdoor-trace`).
   - The tracer reports its own peak RSS via a minimal `--stats` flag printing `trapdoor-trace-stats: peak_rss_kb=<N>` to stderr at exit.

4. **Full Tool Peak RSS**:
   - Peak resident set size of `trapdoor run` (tracer process + Python runtime and analysis structures).

5. **Docker Daemon Footprint**:
   - If Docker is measured, the resident memory of `dockerd` and `containerd` is recorded in addition to the container's isolated memory, providing an honest accounting of the daemon infrastructure required to run containerized workloads ("isolation vs. observation").

---

## 5. Environment & Privacy Safeguards

### Hardware & System Context Recorded
To allow third-party reproducibility, the benchmark records:
- CPU model name (from `/proc/cpuinfo`)
- Physical cores and logical thread count
- CPU scaling governor (from `/sys/devices/system/cpu/.../scaling_governor`)
- Power state (Mains / Battery online state and status)
- Linux kernel version (`uname -r`)
- OS distribution release
- Compiler and toolchain versions (`gcc`, `clang`, `cmake`, `python3`, `node`, `npm`, `strace`, `docker`)
- Machine idle check: 1-minute system load average immediately prior to the benchmark run to verify the host was quiescent.

### Public Privacy & Redaction Invariant
The repository is public. Under **no circumstances** may host-identifying or personal data appear in benchmark logs or committed JSON artifacts:
- **NO** machine hostname (`socket.gethostname()`)
- **NO** user login or account name (`os.getlogin()`, `$USER`)
- **NO** absolute user home directory paths (`/home/...`)
- All file paths in saved results are normalized to project-relative paths or generic placeholders (e.g. `<wheelhouse>`, `<scratch>`, `<npm_cache>`).

---

## 6. Execution Modes & CI Guardrails

1. **Standalone Benchmark Runner (`bench/run.py`)**:
   - Implemented using Python standard library only (no external dependencies).
   - Dynamically parses `tracer/src/seccomp.cpp` to build the syscall filter list.
   - Manages pre-warming caches (`--setup`), executing runs, interleaving conditions, and aggregating statistics.
   - Raw output is saved as machine-readable JSON in `bench/results/<timestamp>.json`.

2. **Smoke Mode (`bench/run.py --smoke`)**:
   - Runs a single iteration across workloads to ensure the benchmark script and fixtures do not rot.
   - Can be invoked during development or pre-commit checks.

3. **CI Policy**:
   - **Never run benchmarks as pass/fail assertions in CI.** Shared virtual machines and cloud runners experience erratic CPU scheduling and noisy-neighbor interference that produce false performance regressions.
   - Published numbers were recorded on a single plugged-in laptop following this methodology; see the README for the exact setup.
