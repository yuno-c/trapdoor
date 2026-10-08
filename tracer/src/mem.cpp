// See mem.h.

#include "mem.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>

namespace trapdoor {
namespace {

bool vm_read(int pid, std::uintptr_t remote, char* dst, std::size_t len) {
    if (len == 0) return true;
    struct iovec local{static_cast<void*>(dst), len};
    struct iovec remote_iov{reinterpret_cast<void*>(remote), len};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote_iov, 1, 0);
    return n == static_cast<ssize_t>(len);
}

}  // namespace

std::string ReadString(int pid, std::uintptr_t addr, std::size_t max_len) {
    if (addr == 0 || max_len == 0) return {};
    std::string out;
    out.reserve(256);
    char buf[1024];
    std::uintptr_t cur = addr;
    std::size_t total = 0;
    bool vm_ok = true;
    while (total < max_len) {
        std::size_t want = sizeof(buf);
        if (want > max_len - total) want = max_len - total;
        struct iovec local{buf, want};
        struct iovec remote{reinterpret_cast<void*>(cur), want};
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n <= 0) {
            vm_ok = false;
            break;
        }
        for (ssize_t i = 0; i < n; ++i) {
            if (buf[i] == '\0') {
                out.append(buf, static_cast<std::size_t>(i));
                return out;
            }
        }
        out.append(buf, static_cast<std::size_t>(n));
        cur += static_cast<std::size_t>(n);
        total += static_cast<std::size_t>(n);
        if (static_cast<std::size_t>(n) < want) break;
    }
    if (vm_ok && !out.empty()) return out;

    // Fallback: PTRACE_PEEKDATA word by word.
    out.clear();
    for (std::size_t off = 0; off < max_len; off += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           reinterpret_cast<void*>(addr + off), nullptr);
        if (word == -1 && errno != 0) return {};
        for (std::size_t i = 0; i < sizeof(long); ++i) {
            char c = static_cast<char>((word >> (i * 8)) & 0xff);
            if (c == '\0') return out;
            out.push_back(c);
            if (out.size() >= max_len) return out;
        }
    }
    return out;
}

std::vector<std::string> ReadArgv(int pid, std::uintptr_t addr,
                                   std::size_t max_args) {
    std::vector<std::string> out;
    if (addr == 0) return out;
    // Read the pointer array in one go (64-bit pointers).
    std::uintptr_t ptrs[33];
    std::size_t want = (max_args + 1) * sizeof(std::uintptr_t);
    if (want > sizeof(ptrs)) want = sizeof(ptrs);
    char raw[sizeof(ptrs)];
    if (!vm_read(pid, addr, raw, want)) {
        // Fallback: peek pointers one by one.
        for (std::size_t i = 0; i < max_args; ++i) {
            errno = 0;
            // Two PEEKDATA reads per 8-byte pointer on 64-bit.
            long lo = ptrace(PTRACE_PEEKDATA, pid,
                             reinterpret_cast<void*>(addr + i * 8), nullptr);
            if (lo == -1 && errno != 0) break;
            long hi = 0;
            if (sizeof(std::uintptr_t) > sizeof(long)) {
                hi = ptrace(PTRACE_PEEKDATA, pid,
                            reinterpret_cast<void*>(addr + i * 8 + 4),
                            nullptr);
                if (hi == -1 && errno != 0) break;
            }
            std::uintptr_t p = static_cast<std::uintptr_t>(
                static_cast<unsigned long>(lo) |
                (static_cast<unsigned long>(hi) << 32));
            if (p == 0) break;
            out.push_back(ReadString(pid, p, 4096));
        }
        return out;
    }
    std::memcpy(ptrs, raw, want);
    std::size_t count = want / sizeof(std::uintptr_t);
    for (std::size_t i = 0; i < count && out.size() < max_args; ++i) {
        if (ptrs[i] == 0) break;
        out.push_back(ReadString(pid, ptrs[i], 4096));
    }
    return out;
}

SockAddr ReadSockaddr(int pid, std::uintptr_t addr, std::size_t len) {
    SockAddr out;
    if (addr == 0 || len < 2) return out;
    unsigned char buf[128];
    std::size_t want = len > sizeof(buf) ? sizeof(buf) : len;
    if (!vm_read(pid, addr, reinterpret_cast<char*>(buf), want)) return out;
    int fam = buf[0] | (buf[1] << 8);
    out.family = fam;
    out.raw_family = fam;
    if (fam == AF_INET) {
        if (want < 8) return out;
        out.port = (buf[2] << 8) | buf[3];
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, buf + 4, ip, sizeof(ip)) == nullptr) return out;
        out.addr = ip;
        out.valid = true;
    } else if (fam == AF_INET6) {
        if (want < 28) return out;
        out.port = (buf[2] << 8) | buf[3];
        char ip[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, buf + 8, ip, sizeof(ip)) == nullptr)
            return out;
        out.addr = ip;
        out.valid = true;
    } else if (fam == AF_UNIX) {
        out.port = 0;
        if (want <= 2) {
            out.addr = "(unnamed)";
        } else if (buf[2] == '\0') {
            out.addr = "@abstract";
        } else {
            std::size_t n = want - 2;
            const char* p = reinterpret_cast<const char*>(buf + 2);
            std::size_t z = 0;
            while (z < n && p[z] != '\0') ++z;
            out.addr.assign(p, z);
        }
        out.valid = true;
    } else {
        out.addr = "?";
        out.valid = true;
    }
    return out;
}

bool ReadMsghdrName(int pid, std::uintptr_t msg_addr, SockAddr* out) {
    // struct msghdr: { void *msg_name; socklen_t msg_namelen; ... }
    // Read the first 16 bytes (pointer + int + padding).
    if (msg_addr == 0 || out == nullptr) return false;
    unsigned char buf[16];
    if (!vm_read(pid, msg_addr, reinterpret_cast<char*>(buf), sizeof(buf)))
        return false;
    std::uintptr_t name = 0;
    unsigned namelen = 0;
    std::memcpy(&name, buf, sizeof(name));
    std::memcpy(&namelen, buf + sizeof(name), sizeof(namelen));
    if (name == 0 || namelen == 0) return false;
    *out = ReadSockaddr(pid, name, namelen);
    return out->valid;
}

std::string ReadLinkPath(const std::string& link) {
    char buf[PATH_MAX];
    ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (n < 0) return {};
    buf[n] = '\0';
    return std::string(buf, static_cast<std::size_t>(n));
}

std::string ProcExe(int pid) {
    std::string l =
        ReadLinkPath("/proc/" + std::to_string(pid) + "/exe");
    return l.empty() ? "?" : l;
}

// Thread group leader (tgid) for a tid; falls back to pid when /proc
// is already gone or unreadable, i.e. treat it as a process.
int ProcTgid(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/status";
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) return pid;
    char line[256];
    int tgid = pid;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "Tgid:", 5) == 0) {
            tgid = std::atoi(line + 5);
            break;
        }
    }
    std::fclose(f);
    return tgid > 0 ? tgid : pid;
}

std::string ProcCwd(int pid) {
    std::string l =
        ReadLinkPath("/proc/" + std::to_string(pid) + "/cwd");
    return l.empty() ? "?" : l;
}

std::string FdPath(int pid, int fd) {
    if (fd < 0) return {};
    std::string l = ReadLinkPath("/proc/" + std::to_string(pid) + "/fd/" +
                                 std::to_string(fd));
    return l;
}

// Resolve symlinks through the *tracee's* root so a symlink alias
// (ln -s ~/.ssh ~/innocent) cannot hide the real target from rules.
// Falls back to the lexical path when the target does not exist
// (entry-only events include failed opens), loops, or races.
static std::string Canonicalize(int pid, const std::string& abspath) {
    if (abspath.empty() || abspath[0] != '/') return abspath;
    std::string via =
        "/proc/" + std::to_string(pid) + "/root" + abspath;
    char* c = realpath(via.c_str(), nullptr);
    if (!c) return abspath;
    std::string out(c);
    free(c);
    return out;
}

std::string ResolveAt(int pid, int dirfd, const std::string& path) {
    if (path.empty()) return path;
    std::string joined;
    if (!path.empty() && path[0] == '/') {
        joined = path;
    } else if (dirfd == AT_FDCWD) {
        std::string cwd = ProcCwd(pid);
        if (cwd.empty() || cwd == "?")
            return path;
        joined = cwd + "/" + path;
    } else {
        std::string base = FdPath(pid, dirfd);
        if (!base.empty() && base[0] == '/' && base.find("socket:[") != 0 &&
            base.find("pipe:[") != 0 && base.find("anon_inode:") != 0) {
            joined = base + "/" + path;
        } else {
            std::string cwd = ProcCwd(pid);
            if (cwd.empty() || cwd == "?") return path;
            joined = cwd + "/" + path;
        }
    }
    // Lexical normalization (no filesystem access: symlinks stay as-is).
    bool absolute = !joined.empty() && joined[0] == '/';
    std::vector<std::string> parts;
    std::string cur;
    for (std::size_t i = 0; i <= joined.size(); ++i) {
        char c = i < joined.size() ? joined[i] : '/';
        if (c == '/') {
            if (cur.empty() || cur == ".") {
                // skip
            } else if (cur == "..") {
                if (!parts.empty() && parts.back() != "..") {
                    parts.pop_back();
                } else if (!absolute) {
                    parts.push_back("..");
                }
            } else {
                parts.push_back(cur);
            }
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    std::string res = absolute ? "/" : "";
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) res += "/";
        res += parts[i];
    }
    std::string lexical =
        res.empty() ? (absolute ? "/" : ".") : res;
    return Canonicalize(pid, lexical);
}

std::string OpenFlagsToString(unsigned long flags) {
    std::string s;
#ifdef O_PATH
    if ((flags & O_PATH) == O_PATH) {
        s = "O_PATH";
    } else
#endif
#ifdef O_TMPFILE
        if ((flags & O_TMPFILE) == O_TMPFILE) {
        s = "O_TMPFILE";
    } else
#endif
    {
        switch (flags & O_ACCMODE) {
            case O_RDONLY:
                s = "O_RDONLY";
                break;
            case O_WRONLY:
                s = "O_WRONLY";
                break;
            case O_RDWR:
                s = "O_RDWR";
                break;
            default:
                s = "O_RDONLY";
                break;
        }
    }
    auto add = [&](unsigned long bit, const char* name) {
        if (flags & bit) {
            s += "|";
            s += name;
        }
    };
#ifdef O_CREAT
    add(O_CREAT, "O_CREAT");
#endif
#ifdef O_EXCL
    add(O_EXCL, "O_EXCL");
#endif
#ifdef O_TRUNC
    add(O_TRUNC, "O_TRUNC");
#endif
#ifdef O_APPEND
    add(O_APPEND, "O_APPEND");
#endif
#ifdef O_NONBLOCK
    add(O_NONBLOCK, "O_NONBLOCK");
#endif
#ifdef O_DSYNC
    add(O_DSYNC, "O_DSYNC");
#endif
#ifdef O_DIRECT
    add(O_DIRECT, "O_DIRECT");
#endif
#ifdef O_LARGEFILE
    add(O_LARGEFILE, "O_LARGEFILE");
#endif
#ifdef O_DIRECTORY
    if ((flags & O_DIRECTORY) && s != "O_TMPFILE") add(O_DIRECTORY, "O_DIRECTORY");
#endif
#ifdef O_NOFOLLOW
    add(O_NOFOLLOW, "O_NOFOLLOW");
#endif
#ifdef O_CLOEXEC
    add(O_CLOEXEC, "O_CLOEXEC");
#endif
#ifdef O_SYNC
    add(O_SYNC, "O_SYNC");
#endif
    return s;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    char hex[] = "0123456789abcdef";
    for (unsigned char c : s) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[(c >> 4) & 0xf];
                    out += hex[c & 0xf];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

double MonotonicSeconds() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) +
           static_cast<double>(ts.tv_nsec) / 1e9;
}

}  // namespace trapdoor
