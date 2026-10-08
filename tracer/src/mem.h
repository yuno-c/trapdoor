// Tracee-memory readers and path/sockaddr helpers (observing only).
//
// WARNING (TOCTOU): another tracee thread can mutate memory between the
// syscall stop and our read. Fine for observation; fatal for enforcement,
// which is why v1 never blocks. See README threat model.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace trapdoor {

// Read a NUL-terminated string from the tracee. Empty on failure.
std::string ReadString(int pid, std::uintptr_t addr,
                       std::size_t max_len = 4096);

// Read a NULL-terminated argv array (capped). Empty entries on failure.
std::vector<std::string> ReadArgv(int pid, std::uintptr_t addr,
                                   std::size_t max_args = 32);

struct SockAddr {
    int family = -1;  // AF_* or -1
    int raw_family = -1;  // numeric family as read (for unknown families)
    std::string addr;  // IP string, unix path, or "?"
    int port = 0;
    bool valid = false;
};

// Read and parse a sockaddr from the tracee.
SockAddr ReadSockaddr(int pid, std::uintptr_t addr, std::size_t len);

// Read struct msghdr.msg_name (for sendmsg) and parse it. False if none.
bool ReadMsghdrName(int pid, std::uintptr_t msg_addr, SockAddr* out);

std::string ReadLinkPath(const std::string& link);
std::string ProcExe(int pid);   // /proc/pid/exe or "?"
int ProcTgid(int pid);          // thread group leader, or pid if unknown
std::string ProcCwd(int pid);   // /proc/pid/cwd or "?"
std::string FdPath(int pid, int fd);

// Resolve (dirfd, path) to an absolute path, lexically normalized.
// Falls back to cwd-relative when dirfd is unreadable.
std::string ResolveAt(int pid, int dirfd, const std::string& path);

std::string OpenFlagsToString(unsigned long flags);
std::string JsonEscape(const std::string& s);
double MonotonicSeconds();

}  // namespace trapdoor
