# Trapdoor

[![CI](https://github.com/yuno-c/trapdoor/actions/workflows/ci.yml/badge.svg)](https://github.com/yuno-c/trapdoor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**See what an install actually does.** Run `npm install`, `pip install`, or any
command under Trapdoor and get a short, readable report of every file it
touched, every network connection it made, and every process it spawned.

No Docker. No VM. No root. No daemon.

```sh
trapdoor run -- npm install
trapdoor run -- pip install requests
```

> **Trapdoor observes. It does not block.** A traced program can detect
> tracing and behave differently, and a clean report means "nothing suspicious
> *this run*", not "safe". Read the [threat model](#threat-model) before
> relying on it.

## Why

Install scripts run with your full user permissions. A `postinstall` hook or a
`setup.py` can read `~/.ssh`, append to your shell config, or phone home, and
most developers run installs without looking. The usual tools either predict
behavior from a package name (static scanning) or need containers or a VM to
observe it. Trapdoor wraps the command you were going to run anyway and
records what really happened.

## Example

A command that reaches for an SSH key, even one that doesn't exist, gets flagged:

```text
$ trapdoor run -- cat ~/.ssh/trapdoor-demo-file
cat: /home/dami/.ssh/trapdoor-demo-file: No such file or directory
trapdoor report
===============

verdict: SUSPICIOUS

process tree
------------
cat (pid 160370)

network endpoints
-----------------
  (none)

notable files (outside node_modules/.git/caches)
-----------------------------------------------
  /home/dami/.ssh/trapdoor-demo-file  (1 event)

rule hits
---------
  [high] secret-access: touched sensitive file /home/dami/.ssh/trapdoor-demo-file
         (coreutils, pid 160370)

note: v1 observes only; it does not block.
note: traced command exited with 1.
```

Failed attempts are reported too, because a script probing for keys is
suspicious whether or not the file exists.

## How it works

```text
trapdoor CLI (Python)  ->  trapdoor-trace (C++, seccomp + ptrace)  ->  your command
        |                              |
   rules, report                 JSON Lines events
```

1. **Tracer (C++).** Launches your command under `ptrace` with a seccomp-bpf
   filter. The filter lets ordinary syscalls run at full speed and wakes the
   tracer only for the ones that matter: file opens, deletes and renames,
   `connect`/`bind`, and `execve`. It follows child processes and threads, and
   resolves every path to an absolute, symlink-free form so rules can't be
   dodged with `chdir` or symlink aliases.
2. **Event stream.** The tracer emits one JSON object per line
   (`file.open`, `file.write`, `file.delete`, `file.rename`, `net.connect`,
   `net.bind`, `proc.exec`, `proc.exit`).
3. **Analyzer (Python).** Collapses noise (system libraries, `node_modules`),
   builds the process tree, evaluates the rules, and prints the report.

The tracer is OS-specific; the analyzer only sees the event stream, so more
backends can be added later without touching the rules.

### Rules (v1)

| Rule | Fires on |
|---|---|
| `secret-access` | Reads of SSH keys, cloud credentials, `.npmrc`, browser profiles, shell history |
| `unexpected-network` | Connections other than to known package registries |
| `fetch-and-execute` | A process writes a file, then executes it |
| `persistence` | Writes to shell startup files, cron, systemd user units, autostart |
| `write-outside-project` | Modifications outside the project directory (low severity) |

`trapdoor rules list` shows the loaded rules.

## Install (from source)

Trapdoor is not on PyPI yet; build it from a clone. Linux x86-64 only for now.

**Requirements:** a C++17 compiler (g++ or clang), CMake, Linux kernel headers,
Python 3.11+. Node.js is only needed to run the npm test fixture.

```sh
git clone https://github.com/yuno-c/trapdoor.git
cd trapdoor

# build the tracer
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# install the Python CLI into a virtual environment
python -m venv .venv
source .venv/bin/activate
pip install -e .

# try it
trapdoor run -- ls
```

A virtual environment is needed on most modern distros, which refuse
`pip install` into the system Python (PEP 668).

**Nix / NixOS users:** run `nix develop` first. It gives you a shell with every
dependency (cmake, g++, Python, pytest, Node), and on NixOS you need it because
those tools aren't installed system-wide. On other distros it is optional.

### Usage

```sh
trapdoor run -- npm install            # terminal report
trapdoor run --json -- pip install .   # structured JSON report
trapdoor run -o events.jsonl -- make   # also write the raw event stream
trapdoor rules list                    # show the loaded rules
```

The traced command's exit code is passed through, so Trapdoor can wrap commands
in scripts.

## Platform support

| Platform | Status |
|---|---|
| Linux x86-64 | Supported. Tested in CI on Ubuntu. |
| Windows | Expected to work inside WSL2 (real Linux kernel); not yet tested. |
| macOS | Not supported. Use a Linux VM or CI. |
| Linux aarch64 | Planned. |

## Threat model

Trapdoor is an **observation aid, not a sandbox**.

- A traced process can detect tracing (`TracerPid` in `/proc/self/status`) and
  stay quiet.
- Time-delayed or conditional behavior (only in CI, only on certain dates) may
  not trigger during the run you observed.
- `io_uring` operations may bypass the syscalls Trapdoor watches. Treat it as a
  blind spot until confirmed otherwise.
- Path arguments are read from the traced process's memory, so another thread
  can change them in between. That is acceptable for observing and is exactly
  why Trapdoor does not try to block.
- Hardlinks and bind mounts have no canonical name, so reading
  `ln ~/.ssh/id_rsa /tmp/x` looks like a read of `/tmp/x`. Fixing this needs
  device and inode tracking and is not done yet.
- Network checks see destination IPs, not hostnames. Registries behind shared
  CDN addresses (for example npm on Cloudflare) cannot be told apart from other
  sites on the same IPs.
- A process can only have one tracer, so Trapdoor does not work inside a
  debugger or another tracer. ptrace restrictions (for example Yama
  `ptrace_scope` or container policy) may also limit tracing on some systems.
- The tracer waits for all descendants, so a command that leaves a long-lived
  daemon running will keep Trapdoor running too.

## Development

```sh
pytest -q
```

The test suite includes a corpus of **harmless simulated attackers** (credential
read, beacon, fetch-and-execute, persistence, and a clean control). Each one must
trigger exactly its expected rules, nothing more and nothing less. Fixtures run
only under a fake `$HOME` and refuse to start otherwise; they never touch real
credentials and only talk to loopback.

## Roadmap

- [x] seccomp + ptrace tracing core with a JSON event stream
- [x] Analyzer, rules and terminal report
- [x] Simulated-attacker test corpus and CI
- [ ] Published benchmarks (no performance claims until then)
- [ ] Behavior diffing between package versions (`trapdoor diff`)
- [ ] CI mode (`--ci`, non-zero exit on rule hits) and PyPI packaging
- [ ] Optional enforcement mode (Landlock / bubblewrap)
- [ ] aarch64, native Windows backend

## License

MIT. See [LICENSE](LICENSE).
