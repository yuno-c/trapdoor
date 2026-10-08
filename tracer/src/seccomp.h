// Seccomp-bpf filter for trapdoor-trace (Linux x86-64).
//
// Returns SECCOMP_RET_TRACE for the watched syscalls, SECCOMP_RET_ALLOW
// for everything else. The kernel runs untraced syscalls at full speed;
// only watched ones wake the tracer via PTRACE_EVENT_SECCOMP.
// Requires PR_SET_NO_NEW_PRIVS before installation (unprivileged use).

#pragma once

#include <vector>

struct sock_filter;  // <linux/filter.h>

namespace trapdoor {

// Watched syscall numbers (x86-64). Built from __NR_* where available so a
// missing number on an older header is skipped rather than breaking the build.
std::vector<int> WatchedSyscalls();

// Build the BPF program. TRACE is the last instruction; ALLOW precedes it.
std::vector<sock_filter> BuildFilter();

// Install NO_NEW_PRIVS + the filter in the calling (to-be-traced) process.
// Returns 0 on success, -1 on failure with errno set.
int InstallFilter();

}  // namespace trapdoor
