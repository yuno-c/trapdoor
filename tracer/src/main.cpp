// trapdoor-trace (Milestone 1: seccomp-bpf + ptrace core, JSON event stream).
//
// Launch: fork; child PTRACES_TRACEME, stops for options, installs the
// seccomp filter (TRACE only watched syscalls), execs the target.
// Parent: follows forks/clones/execs, reads syscall args from tracee
// memory, emits one JSON object per line on stdout (schema v1).
//
// v1 observes only. TOCTOU races are accepted; see mem.h. If the tracer
// dies, PTRACE_O_EXITKILL kills the target so no orphaned tracees remain.
// Tool failures exit 2; otherwise the root target's exit code propagates.
//
// x86-64 only in v1; other arches arrive behind a clean abstraction.

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "mem.h"
#include "seccomp.h"

namespace {

using trapdoor::FdPath;
using trapdoor::JsonEscape;
using trapdoor::MonotonicSeconds;
using trapdoor::OpenFlagsToString;
using trapdoor::ProcCwd;
using trapdoor::ProcExe;
using trapdoor::ReadArgv;
using trapdoor::ReadMsghdrName;
using trapdoor::ReadSockaddr;
using trapdoor::ProcTgid;
using trapdoor::ReadString;
using trapdoor::ResolveAt;
using trapdoor::SockAddr;

constexpr int kEventVersion = 1;
constexpr long kTraceOptions = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEFORK |
                               PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                               PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;

void usage(const char* prog) {
    std::fprintf(stderr,
                 "usage: %s [-o EVENTS.jsonl] -- <command> [args...]\n"
                 "  Events go to stdout by default. Use -o so the tracee's\n"
                 "  own stdout cannot interleave with the event stream.\n",
                 prog);
}

double g_start = 0.0;
FILE* g_out = stdout;

void emit_line(int pid, int ppid, const std::string& exe,
               const std::string& kind, const std::string& extra) {
    double t = MonotonicSeconds() - g_start;
    std::string line;
    line.reserve(256 + extra.size());
    char head[256];
    std::snprintf(head, sizeof(head),
                  "{\"v\":%d,\"t\":%.3f,\"pid\":%d,\"ppid\":%d,\"exe\":\"%s\","
                  "\"kind\":\"%s\"",
                  kEventVersion, t, pid, ppid, JsonEscape(exe).c_str(),
                  kind.c_str());
    line += head;
    if (!extra.empty()) {
        line += ",";
        line += extra;
    }
    line += "}\n";
    std::fwrite(line.data(), 1, line.size(), g_out);
    std::fflush(g_out);  // Keep the stream complete even if we crash.
}

std::string quoted_array(const std::vector<std::string>& v) {
    std::string s = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) s += ",";
        s += "\"";
        s += JsonEscape(v[i]);
        s += "\"";
    }
    s += "]";
    return s;
}

std::string sock_extra(const SockAddr& sa) {
    std::string fam = sa.family == AF_INET    ? "inet"
                      : sa.family == AF_INET6 ? "inet6"
                      : sa.family == AF_UNIX  ? "unix"
                                              : "?";
    std::string addr = sa.addr;
    if (fam == "?")
        addr = "af:" + std::to_string(sa.raw_family);  // e.g. af:16 netlink
    char buf[512];
    std::snprintf(buf, sizeof(buf), "\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"",
                  JsonEscape(addr).c_str(), sa.port, fam.c_str());
    return buf;
}

// Best-effort ppid from /proc when our table misses (threads, races).
int stat_ppid(int pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return 0;
    char buf[1024];
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    if (n == 0) return 0;
    buf[n] = '\0';
    const char* rp = std::strrchr(buf, ')');
    if (!rp) return 0;
    int ppid = 0;
    // Format after comm: " state ppid ...".
    if (std::sscanf(rp + 1, " %*c %d", &ppid) == 1) return ppid;
    return 0;
}

bool read_u64(int pid, std::uintptr_t addr, unsigned long long* out) {
    struct iovec local{out, sizeof(*out)};
    struct iovec remote{reinterpret_cast<void*>(addr), sizeof(*out)};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(sizeof(*out));
}

struct Tracer {
    std::map<int, int> ppid;  // pid -> ppid (0 = trace root)
    std::map<int, std::string> exe_cache;  // last-seen exe per pid
    std::map<int, int> thread_leader;  // tid -> tgid (only if tid != tgid)
    std::set<int> live;

    int get_ppid(int pid) {
        auto it = ppid.find(pid);
        if (it != ppid.end()) return it->second;
        int p = stat_ppid(pid);
        ppid[pid] = p;
        return p;
    }

    std::string get_exe(int pid) {
        std::string e = ProcExe(pid);
        if (e != "?") exe_cache[pid] = e;
        auto it = exe_cache.find(pid);
        return it == exe_cache.end() ? "?" : it->second;
    }

    void on_seccomp(int pid, long nr, const struct user_regs_struct& r) {
        const int pp = get_ppid(pid);
        const std::string exe = get_exe(pid);
#if defined(__x86_64__)
        const auto RDI = static_cast<unsigned long long>(r.rdi);
        const auto RSI = static_cast<unsigned long long>(r.rsi);
        const auto RDX = static_cast<unsigned long long>(r.rdx);
        const auto R10 = static_cast<unsigned long long>(r.r10);
        const auto R8 = static_cast<unsigned long long>(r.r8);
#endif

#if defined(__NR_openat)
        if (nr == __NR_openat) {
            std::string raw = ReadString(pid, (std::uintptr_t)RSI);
            if (raw.empty()) return;
            std::string path = ResolveAt(pid, (int)(int32_t)RDI, raw);
            std::string extra = "\"path\":\"" + JsonEscape(path) +
                                "\",\"flags\":\"" +
                                JsonEscape(OpenFlagsToString(RDX)) + "\"";
            emit_line(pid, pp, exe, "file.open", extra);
            return;
        }
#endif
#if defined(__NR_openat2)
        if (nr == __NR_openat2) {
            std::string raw = ReadString(pid, (std::uintptr_t)RSI);
            if (raw.empty()) return;
            std::string path = ResolveAt(pid, (int)(int32_t)RDI, raw);
            unsigned long long how_flags = 0;
            std::string flags = "?";
            if (read_u64(pid, (std::uintptr_t)RDX, &how_flags))
                flags = OpenFlagsToString((unsigned long)how_flags);
            std::string extra = "\"path\":\"" + JsonEscape(path) +
                                "\",\"flags\":\"" + JsonEscape(flags) + "\"";
            emit_line(pid, pp, exe, "file.open", extra);
            return;
        }
#endif
#if defined(__NR_unlink)
        if (nr == __NR_unlink) {
            std::string raw = ReadString(pid, (std::uintptr_t)RDI);
            if (raw.empty()) return;
            std::string path = ResolveAt(pid, AT_FDCWD, raw);
            emit_line(pid, pp, exe, "file.delete",
                      "\"path\":\"" + JsonEscape(path) + "\"");
            return;
        }
#endif
#if defined(__NR_unlinkat)
        if (nr == __NR_unlinkat) {
            std::string raw = ReadString(pid, (std::uintptr_t)RSI);
            if (raw.empty()) return;
            std::string path = ResolveAt(pid, (int)(int32_t)RDI, raw);
            emit_line(pid, pp, exe, "file.delete",
                      "\"path\":\"" + JsonEscape(path) + "\"");
            return;
        }
#endif
#if defined(__NR_rename)
        if (nr == __NR_rename) {
            std::string o = ReadString(pid, (std::uintptr_t)RDI);
            std::string n = ReadString(pid, (std::uintptr_t)RSI);
            if (o.empty() || n.empty()) return;
            emit_line(pid, pp, exe, "file.rename",
                      "\"src\":\"" + JsonEscape(ResolveAt(pid, AT_FDCWD, o)) +
                          "\",\"dst\":\"" +
                          JsonEscape(ResolveAt(pid, AT_FDCWD, n)) + "\"");
            return;
        }
#endif
#if defined(__NR_renameat)
        if (nr == __NR_renameat) {
            std::string o = ReadString(pid, (std::uintptr_t)RSI);
            std::string n = ReadString(pid, (std::uintptr_t)R10);
            if (o.empty() || n.empty()) return;
            emit_line(pid, pp, exe, "file.rename",
                      "\"src\":\"" +
                          JsonEscape(ResolveAt(pid, (int)(int32_t)RDI, o)) +
                          "\",\"dst\":\"" +
                          JsonEscape(ResolveAt(pid, (int)(int32_t)RDX, n)) +
                          "\"");
            return;
        }
#endif
#if defined(__NR_renameat2)
        if (nr == __NR_renameat2) {
            std::string o = ReadString(pid, (std::uintptr_t)RSI);
            std::string n = ReadString(pid, (std::uintptr_t)R10);
            if (o.empty() || n.empty()) return;
            emit_line(pid, pp, exe, "file.rename",
                      "\"src\":\"" +
                          JsonEscape(ResolveAt(pid, (int)(int32_t)RDI, o)) +
                          "\",\"dst\":\"" +
                          JsonEscape(ResolveAt(pid, (int)(int32_t)RDX, n)) +
                          "\"");
            return;
        }
#endif
#if defined(__NR_symlink)
        if (nr == __NR_symlink) {
            std::string target = ReadString(pid, (std::uintptr_t)RDI);
            std::string link = ReadString(pid, (std::uintptr_t)RSI);
            if (link.empty()) return;
            emit_line(pid, pp, exe, "file.write",
                      "\"path\":\"" +
                          JsonEscape(ResolveAt(pid, AT_FDCWD, link)) +
                          "\",\"target\":\"" + JsonEscape(target) + "\"");
            return;
        }
#endif
#if defined(__NR_symlinkat)
        if (nr == __NR_symlinkat) {
            std::string target = ReadString(pid, (std::uintptr_t)RDI);
            std::string link = ReadString(pid, (std::uintptr_t)RDX);
            if (link.empty()) return;
            emit_line(pid, pp, exe, "file.write",
                      "\"path\":\"" +
                          JsonEscape(ResolveAt(pid, (int)(int32_t)RSI, link)) +
                          "\",\"target\":\"" + JsonEscape(target) + "\"");
            return;
        }
#endif
#if defined(__NR_chmod)
        if (nr == __NR_chmod) {
            std::string raw = ReadString(pid, (std::uintptr_t)RDI);
            if (raw.empty()) return;
            emit_line(pid, pp, exe, "file.write",
                      "\"path\":\"" +
                          JsonEscape(ResolveAt(pid, AT_FDCWD, raw)) + "\"");
            return;
        }
#endif
#if defined(__NR_fchmod)
        if (nr == __NR_fchmod) {
            std::string p = FdPath(pid, (int)(int32_t)RDI);
            if (p.empty()) return;
            emit_line(pid, pp, exe, "file.write",
                      "\"path\":\"" + JsonEscape(p) + "\"");
            return;
        }
#endif
#if defined(__NR_fchmodat)
        if (nr == __NR_fchmodat) {
            std::string raw = ReadString(pid, (std::uintptr_t)RSI);
            if (raw.empty()) return;
            emit_line(pid, pp, exe, "file.write",
                      "\"path\":\"" +
                          JsonEscape(ResolveAt(pid, (int)(int32_t)RDI, raw)) +
                          "\"");
            return;
        }
#endif
        if (nr == __NR_connect
#if defined(__NR_bind)
            || nr == __NR_bind
#endif
        ) {
            SockAddr sa =
                ReadSockaddr(pid, (std::uintptr_t)RSI, (size_t)RDX);
            if (!sa.valid) return;
            emit_line(pid, pp, exe,
                      nr == __NR_connect ? "net.connect" : "net.bind",
                      sock_extra(sa));
            return;
        }
#if defined(__NR_sendto)
        if (nr == __NR_sendto) {
            // sendto args: rdi fd, rsi buf, rdx len, r10 flags,
            // r8 dest_addr, r9 addrlen. Connected sockets pass NULL:
            // those are covered by the earlier connect event, so skip.
            std::uintptr_t daddr = (std::uintptr_t)R8;
            std::size_t dlen = (std::size_t)r.r9;
            if (daddr == 0 || dlen < 2) return;
            SockAddr sa = ReadSockaddr(pid, daddr, dlen);
            if (!sa.valid) return;
            emit_line(pid, pp, exe, "net.connect", sock_extra(sa));
            return;
        }
#endif
#if defined(__NR_sendmsg)
        if (nr == __NR_sendmsg) {
            SockAddr sa;
            if (!ReadMsghdrName(pid, (std::uintptr_t)RSI, &sa)) return;
            emit_line(pid, pp, exe, "net.connect", sock_extra(sa));
            return;
        }
#endif
#if defined(__NR_execve)
        if (nr == __NR_execve) {
            std::string raw = ReadString(pid, (std::uintptr_t)RDI);
            if (raw.empty()) return;
            std::vector<std::string> argv =
                ReadArgv(pid, (std::uintptr_t)RSI);
            std::string extra = "\"path\":\"" +
                                JsonEscape(ResolveAt(pid, AT_FDCWD, raw)) +
                                "\",\"argv\":" + quoted_array(argv);
            emit_line(pid, pp, exe, "proc.exec", extra);
            return;
        }
#endif
#if defined(__NR_execveat)
        if (nr == __NR_execveat) {
            std::string raw = ReadString(pid, (std::uintptr_t)RSI);
            if (raw.empty()) return;
            std::vector<std::string> argv =
                ReadArgv(pid, (std::uintptr_t)RDX);
            std::string extra = "\"path\":\"" +
                                JsonEscape(ResolveAt(pid, (int)(int32_t)RDI,
                                                     raw)) +
                                "\",\"argv\":" + quoted_array(argv);
            emit_line(pid, pp, exe, "proc.exec", extra);
            return;
        }
#endif
        // clone/fork/vfork/clone3: followed via ptrace events; no event.
    }

    int run(int root_pid) {
        ppid[root_pid] = 0;
        live.insert(root_pid);
        int root_code = 0;
        bool root_done = false;

        while (!live.empty()) {
            int status = 0;
            int pid = waitpid(-1, &status, __WALL);
            if (pid < 0) {
                if (errno == EINTR) continue;
                if (errno == ECHILD) break;
                std::perror("trapdoor-trace: waitpid");
                return 2;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                int code = WIFEXITED(status) ? WEXITSTATUS(status)
                                             : 128 + WTERMSIG(status);
                auto it = ppid.find(pid);
                int pp = it == ppid.end() ? 0 : it->second;
                // /proc/PID/exe vanishes at exit; use the cached exe so
                // exit events stay attributed to the right program.
                auto eit = exe_cache.find(pid);
                std::string exe =
                    eit == exe_cache.end() ? "?" : eit->second;
                std::string extra = "\"code\":" + std::to_string(code);
                if (WIFSIGNALED(status))
                    extra += ",\"signal\":" + std::to_string(WTERMSIG(status));
                // exe may be empty post-exit; keep the field for schema.
                double t = MonotonicSeconds() - g_start;
                char head[256];
                std::snprintf(
                    head, sizeof(head),
                    "{\"v\":%d,\"t\":%.3f,\"pid\":%d,\"ppid\":%d,\"exe\":"
                    "\"%s\",\"kind\":\"proc.exit\",%s}\n",
                    kEventVersion, t, pid, pp,
                    JsonEscape(exe).c_str(), extra.c_str());
                std::fwrite(head, 1, std::strlen(head), g_out);
                std::fflush(g_out);
                live.erase(pid);
                ppid.erase(pid);
                exe_cache.erase(pid);
                if (pid == root_pid) {
                    root_code = code;
                    root_done = true;
                }
                continue;
            }
            if (!WIFSTOPPED(status)) continue;
            int sig = WSTOPSIG(status);
            int event = (status >> 16) & 0xffff;

            if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
                struct user_regs_struct regs{};
                if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
#if defined(__x86_64__)
                    on_seccomp(pid, (long)regs.orig_rax, regs);
#endif
                }
                if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0 &&
                    errno != ESRCH) {
                    std::perror("trapdoor-trace: PTRACE_CONT");
                    return 2;
                }
            } else if (sig == SIGTRAP &&
                       (event == PTRACE_EVENT_FORK ||
                        event == PTRACE_EVENT_VFORK ||
                        event == PTRACE_EVENT_CLONE)) {
                unsigned long msg = 0;
                if (ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &msg) == 0) {
                    int child = (int)msg;
                    ppid[child] = pid;
                    live.insert(child);
                    // Seed exe now: threads that never make a watched syscall
                    // would otherwise exit with exe "?" (/proc gone at exit).
                    std::string e = ProcExe(child);
                    if (e != "?") exe_cache[child] = e;
                    // Threads carry their group leader's pid so the analyzer
                    // can fold them under the leader instead of the leader's
                    // children. Absent for plain fork/clone (tgid == pid).
                    int tgid = ProcTgid(child);
                    if (tgid > 0 && tgid != child) thread_leader[child] = tgid;
                }
                if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0 &&
                    errno != ESRCH) {
                    std::perror("trapdoor-trace: PTRACE_CONT");
                    return 2;
                }
            } else if (sig == SIGTRAP &&
                       (event == PTRACE_EVENT_EXEC
#ifdef PTRACE_EVENT_STOP
                        || event == PTRACE_EVENT_STOP
#endif
                        || event == 0)) {
                if (event == PTRACE_EVENT_EXEC) {
                    // Refresh the exe cache: the process just became a
                    // different program (readlink is valid again post-exec).
                    std::string e = ProcExe(pid);
                    if (e != "?") exe_cache[pid] = e;
                }
                if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0 &&
                    errno != ESRCH) {
                    std::perror("trapdoor-trace: PTRACE_CONT");
                    return 2;
                }
            } else {
                // Real signal (including SIGSTOP of new children): forward.
                void* data = reinterpret_cast<void*>((long)sig);
                if (ptrace(PTRACE_CONT, pid, nullptr, data) != 0 &&
                    errno != ESRCH) {
                    std::perror("trapdoor-trace: PTRACE_CONT");
                    return 2;
                }
            }
        }
        std::fflush(g_out);
        return root_done ? root_code : 0;
    }
};

}  // namespace

int main(int argc, char* argv[]) {
    const char* out_path = nullptr;
    int cmd_at = 1;
    // Optional tracer flags come before the "--" separator.
    while (cmd_at < argc && argv[cmd_at][0] == '-' && argv[cmd_at][1] != '\0' &&
           std::strcmp(argv[cmd_at], "--") != 0) {
        if (std::strcmp(argv[cmd_at], "-o") == 0 && cmd_at + 1 < argc) {
            out_path = argv[cmd_at + 1];
            cmd_at += 2;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (cmd_at < argc && std::strcmp(argv[cmd_at], "--") == 0) ++cmd_at;
    if (cmd_at >= argc) {
        usage(argv[0]);
        return 2;
    }
    char** cmd = &argv[cmd_at];

    if (out_path) {
        // O_CLOEXEC: the exec'd target must not inherit the event stream.
        int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                      0644);
        if (fd < 0) {
            std::fprintf(stderr, "trapdoor-trace: open '%s': %s\n", out_path,
                         std::strerror(errno));
            return 2;
        }
        g_out = fdopen(fd, "w");
        if (!g_out) {
            std::fprintf(stderr, "trapdoor-trace: fdopen: %s\n",
                         std::strerror(errno));
            return 2;
        }
    }

#if !defined(__x86_64__)
    std::fprintf(stderr,
                 "trapdoor-trace M1 supports x86-64 only (see README).\n");
    return 2;
#endif

    std::signal(SIGPIPE, SIG_IGN);
    g_start = MonotonicSeconds();

    pid_t child = fork();
    if (child == -1) {
        std::perror("trapdoor-trace: fork");
        return 2;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            std::perror("trapdoor-trace: PTRACE_TRACEME");
            _exit(2);
        }
        raise(SIGSTOP);  // Let the parent install OPTIONS first.
        if (trapdoor::InstallFilter() != 0) {
            std::perror("trapdoor-trace: seccomp install");
            _exit(2);
        }
        execvp(cmd[0], cmd);
        std::fprintf(stderr, "trapdoor-trace: execvp '%s': %s\n", cmd[0],
                     std::strerror(errno));
        _exit(127);
    }

    // First stop: the child's SIGSTOP. Install trace options, then run.
    int status = 0;
    if (waitpid(child, &status, __WALL) < 0) {
        std::perror("trapdoor-trace: waitpid");
        return 2;
    }
    if (!WIFSTOPPED(status)) {
        std::fprintf(stderr, "trapdoor-trace: unexpected first stop\n");
        return 2;
    }
    if (ptrace(PTRACE_SETOPTIONS, child, nullptr,
               reinterpret_cast<void*>(kTraceOptions)) != 0) {
        std::perror("trapdoor-trace: PTRACE_SETOPTIONS");
        return 2;
    }
    if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0) {
        std::perror("trapdoor-trace: PTRACE_CONT");
        return 2;
    }

    Tracer t;
    return t.run(child);
}
