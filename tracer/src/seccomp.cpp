// See seccomp.h.

#include "seccomp.h"

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/types.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE 0x7ff00000U
#endif

namespace trapdoor {
namespace {

// Push a watched nr if the platform header defines it.
void maybe_add(std::vector<int>& out, long nr) {
    if (nr >= 0) out.push_back(static_cast<int>(nr));
}

}  // namespace

std::vector<int> WatchedSyscalls() {
    std::vector<int> out;
#if defined(__NR_openat)
    maybe_add(out, __NR_openat);
#endif
#if defined(__NR_openat2)
    maybe_add(out, __NR_openat2);
#endif
#if defined(__NR_unlink)
    maybe_add(out, __NR_unlink);
#endif
#if defined(__NR_unlinkat)
    maybe_add(out, __NR_unlinkat);
#endif
#if defined(__NR_rename)
    maybe_add(out, __NR_rename);
#endif
#if defined(__NR_renameat)
    maybe_add(out, __NR_renameat);
#endif
#if defined(__NR_renameat2)
    maybe_add(out, __NR_renameat2);
#endif
#if defined(__NR_symlink)
    maybe_add(out, __NR_symlink);
#endif
#if defined(__NR_symlinkat)
    maybe_add(out, __NR_symlinkat);
#endif
#if defined(__NR_chmod)
    maybe_add(out, __NR_chmod);
#endif
#if defined(__NR_fchmod)
    maybe_add(out, __NR_fchmod);
#endif
#if defined(__NR_fchmodat)
    maybe_add(out, __NR_fchmodat);
#endif
#if defined(__NR_connect)
    maybe_add(out, __NR_connect);
#endif
#if defined(__NR_bind)
    maybe_add(out, __NR_bind);
#endif
#if defined(__NR_sendto)
    maybe_add(out, __NR_sendto);
#endif
#if defined(__NR_sendmsg)
    maybe_add(out, __NR_sendmsg);
#endif
#if defined(__NR_execve)
    maybe_add(out, __NR_execve);
#endif
#if defined(__NR_execveat)
    maybe_add(out, __NR_execveat);
#endif
    // Process spawns are followed via TRACEFORK/CLONE/EXEC events, but the
    // syscalls themselves are also traced so the spawner is attributed.
#if defined(__NR_clone)
    maybe_add(out, __NR_clone);
#endif
#if defined(__NR_clone3)
    maybe_add(out, __NR_clone3);
#endif
#if defined(__NR_fork)
    maybe_add(out, __NR_fork);
#endif
#if defined(__NR_vfork)
    maybe_add(out, __NR_vfork);
#endif
    return out;
}

std::vector<sock_filter> BuildFilter() {
    std::vector<int> watch = WatchedSyscalls();
    const size_t n = watch.size();

    std::vector<sock_filter> f;
    f.reserve(5 + n);
    // Load arch; if != x86-64, allow (we only filter our own arch).
    f.push_back(BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                         offsetof(struct seccomp_data, arch)));
    f.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    f.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
    // Load syscall number.
    f.push_back(BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                         offsetof(struct seccomp_data, nr)));
    // One JEQ per watched nr. At check i (overall index 4+i), TRACE lives
    // at 4+n+1, so the forward jump is (n - i). Mismatch falls through.
    for (size_t i = 0; i < n; ++i) {
        // n is ~25 well below 255; the macro stores jt as __u8.
        __u8 jt = static_cast<__u8>(n - i);
        f.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                             static_cast<unsigned>(watch[i]), jt, 0));
    }
    f.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
    f.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE));
    return f;
}

int InstallFilter() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    std::vector<sock_filter> f = BuildFilter();
    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(f.size());
    prog.filter = f.data();
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

}  // namespace trapdoor
