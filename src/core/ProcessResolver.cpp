#include "core/ProcessResolver.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#elif defined(__APPLE__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <libproc.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace core {

    size_t ProcessResolver::EndpointHash::operator()(const Endpoint& e) const noexcept {
        size_t h = std::hash<std::string>{}(e.ip);
        h ^= std::hash<uint16_t>{}(e.port) + 0x9e3779b9u + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(e.protocol) + 0x9e3779b9u + (h << 6) + (h >> 2);
        return h;
    }

    ProcessResolver::ProcessResolver() {
        refreshLocalAddresses();
        refreshTables();
    }

    std::string ProcessResolver::lookup(const ParsedPacket& packet) {
        if (packet.protocol != "TCP" && packet.protocol != "UDP") return {};
        if (packet.srcPort == 0 && packet.dstPort == 0) return {};

        const auto now = std::chrono::steady_clock::now();
        if (now - m_lastRefresh > std::chrono::milliseconds(1500)) {
            if (!m_localsLoaded) refreshLocalAddresses();
            refreshTables();
        }

        const auto tryLookup = [&](const std::string& ip, uint16_t port) -> std::string {
            if (!m_localIps.contains(ip)) return {};
            Endpoint key{ip, port, packet.protocol};
            auto it = m_endpointToPid.find(key);
            if (it == m_endpointToPid.end()) {
                // UDP and listening sockets often bind to 0.0.0.0 / ::.
                Endpoint anyV4{"0.0.0.0", port, packet.protocol};
                it = m_endpointToPid.find(anyV4);
                if (it == m_endpointToPid.end()) {
                    Endpoint anyV6{"::", port, packet.protocol};
                    it = m_endpointToPid.find(anyV6);
                    if (it == m_endpointToPid.end()) return {};
                }
            }
            auto nameIt = m_pidToName.find(it->second);
            return nameIt == m_pidToName.end() ? std::string{} : nameIt->second;
        };

        if (auto name = tryLookup(packet.srcIP, packet.srcPort); !name.empty()) return name;
        if (auto name = tryLookup(packet.dstIP, packet.dstPort); !name.empty()) return name;
        return {};
    }

#ifdef _WIN32

    namespace {
        std::string wideToUtf8(const wchar_t* ws) {
            if (!ws || !*ws) return {};
            int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
            if (len <= 1) return {};
            std::string out(static_cast<size_t>(len - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), len, nullptr, nullptr);
            return out;
        }

        std::string processNameForPid(uint32_t pid) {
            if (pid == 0) return "System Idle";
            if (pid == 4) return "System";
            HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!handle) return {};
            wchar_t path[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            std::string name;
            if (QueryFullProcessImageNameW(handle, 0, path, &size)) {
                std::wstring ws(path);
                if (const size_t slash = ws.find_last_of(L"\\/"); slash != std::wstring::npos) {
                    ws = ws.substr(slash + 1);
                }
                if (ws.size() > 4 && (ws.compare(ws.size() - 4, 4, L".exe") == 0
                                   || ws.compare(ws.size() - 4, 4, L".EXE") == 0)) {
                    ws = ws.substr(0, ws.size() - 4);
                }
                name = wideToUtf8(ws.c_str());
            }
            CloseHandle(handle);
            return name;
        }
    }

    void ProcessResolver::refreshLocalAddresses() {
        ULONG bufferSize = 16 * 1024;
        std::vector<BYTE> buffer(bufferSize);
        auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        DWORD result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &bufferSize);
        if (result == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(bufferSize);
            addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &bufferSize);
        }
        if (result != NO_ERROR) return;

        m_localIps.clear();
        for (auto* adapter = addresses; adapter; adapter = adapter->Next) {
            for (auto* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                if (!ua->Address.lpSockaddr) continue;
                char ip[INET6_ADDRSTRLEN] = {};
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                    if (inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip))) {
                        m_localIps.insert(ip);
                    }
                } else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    auto* sa = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                    if (inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip))) {
                        m_localIps.insert(ip);
                    }
                }
            }
        }
        m_localIps.insert("127.0.0.1");
        m_localIps.insert("::1");
        m_localsLoaded = true;
    }

    std::string ProcessResolver::findOrResolvePidName(uint32_t pid) {
        if (auto it = m_pidToName.find(pid); it != m_pidToName.end()) return it->second;
        std::string name = processNameForPid(pid);
        m_pidToName.emplace(pid, name);
        return name;
    }

    void ProcessResolver::refreshTables() {
        m_endpointToPid.clear();
        m_lastRefresh = std::chrono::steady_clock::now();

        std::unordered_set<uint32_t> seenPids;

        const auto pushIpv4 = [&](DWORD addr, uint16_t port, const char* protocol, uint32_t pid) {
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &addr, ip, sizeof(ip));
            m_endpointToPid[Endpoint{ip, port, protocol}] = pid;
            seenPids.insert(pid);
        };
        const auto pushIpv6 = [&](const UCHAR* addr, uint16_t port, const char* protocol, uint32_t pid) {
            char ip[INET6_ADDRSTRLEN] = {};
            inet_ntop(AF_INET6, addr, ip, sizeof(ip));
            m_endpointToPid[Endpoint{ip, port, protocol}] = pid;
            seenPids.insert(pid);
        };

        // TCP IPv4
        {
            DWORD size = 0;
            GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size > 0) {
                std::vector<BYTE> buf(size);
                if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const auto& row = table->table[i];
                        const uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                        pushIpv4(row.dwLocalAddr, port, "TCP", row.dwOwningPid);
                    }
                }
            }
        }

        // UDP IPv4
        {
            DWORD size = 0;
            GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (size > 0) {
                std::vector<BYTE> buf(size);
                if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET,
                        UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const auto& row = table->table[i];
                        const uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                        pushIpv4(row.dwLocalAddr, port, "UDP", row.dwOwningPid);
                    }
                }
            }
        }

        // TCP IPv6
        {
            DWORD size = 0;
            GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size > 0) {
                std::vector<BYTE> buf(size);
                if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6,
                        TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const auto& row = table->table[i];
                        const uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                        pushIpv6(row.ucLocalAddr, port, "TCP", row.dwOwningPid);
                    }
                }
            }
        }

        // UDP IPv6
        {
            DWORD size = 0;
            GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (size > 0) {
                std::vector<BYTE> buf(size);
                if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6,
                        UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                    auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
                    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                        const auto& row = table->table[i];
                        const uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                        pushIpv6(row.ucLocalAddr, port, "UDP", row.dwOwningPid);
                    }
                }
            }
        }

        // Resolve names lazily but eagerly enough to fill the table quickly.
        for (const uint32_t pid : seenPids) findOrResolvePidName(pid);
    }

#elif defined(__linux__) || defined(__APPLE__)

    namespace {
        // getifaddrs is the POSIX way to enumerate local interface IPs. Shared
        // between Linux and macOS since both expose the same API.
        void collectInterfaceAddresses(std::unordered_set<std::string>& out) {
            ifaddrs* ifa = nullptr;
            if (getifaddrs(&ifa) != 0) return;
            for (auto* p = ifa; p; p = p->ifa_next) {
                if (!p->ifa_addr) continue;
                char buf[INET6_ADDRSTRLEN] = {};
                if (p->ifa_addr->sa_family == AF_INET) {
                    auto* sa = reinterpret_cast<sockaddr_in*>(p->ifa_addr);
                    if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) {
                        out.insert(buf);
                    }
                } else if (p->ifa_addr->sa_family == AF_INET6) {
                    auto* sa = reinterpret_cast<sockaddr_in6*>(p->ifa_addr);
                    if (inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf))) {
                        // Strip any IPv6 zone id ("fe80::1%eth0" -> "fe80::1") so it
                        // matches the form captured packets use.
                        std::string s = buf;
                        if (auto pos = s.find('%'); pos != std::string::npos) {
                            s.resize(pos);
                        }
                        out.insert(std::move(s));
                    }
                }
            }
            freeifaddrs(ifa);
            out.insert("127.0.0.1");
            out.insert("::1");
        }
    }

#endif

#ifdef __linux__

    namespace {
        // /proc/net/tcp encodes the local IPv4 address as a hex u32 in *host*
        // byte order — so on a little-endian Linux box, strtoul + inet_ntop on
        // the result happens to round-trip to the correct dotted-quad. The
        // observation cuts both ways on big-endian, but the kernel formats with
        // the same host-byte-order convention there too, so the trick is
        // endian-stable in practice.
        bool parseHexIpv4(const std::string& hex, char* out, size_t outSize) {
            if (hex.size() != 8) return false;
            const uint32_t addr = static_cast<uint32_t>(std::strtoul(hex.c_str(), nullptr, 16));
            return inet_ntop(AF_INET, &addr, out, static_cast<socklen_t>(outSize)) != nullptr;
        }

        // /proc/net/tcp6: four 8-char groups, each a host-byte-order u32. Same
        // endian property as parseHexIpv4 — copying the parsed u32s into a 16
        // byte buffer yields the correct in6_addr.
        bool parseHexIpv6(const std::string& hex, char* out, size_t outSize) {
            if (hex.size() != 32) return false;
            uint8_t addr[16];
            for (int i = 0; i < 4; ++i) {
                const uint32_t group = static_cast<uint32_t>(
                    std::strtoul(hex.substr(static_cast<size_t>(i) * 8, 8).c_str(), nullptr, 16));
                std::memcpy(addr + i * 4, &group, 4);
            }
            return inet_ntop(AF_INET6, addr, out, static_cast<socklen_t>(outSize)) != nullptr;
        }

        struct SocketEntry {
            std::string ip;
            uint16_t port;
            std::string protocol;
            uint64_t inode;
        };

        void appendProcNetTable(std::vector<SocketEntry>& out,
                                const char* path, const char* protocol, bool ipv6) {
            std::ifstream f(path);
            if (!f) return;
            std::string line;
            std::getline(f, line); // skip header
            while (std::getline(f, line)) {
                std::istringstream iss(line);
                std::string sl, local, remote, st, txrx, trtm, retr, uid, timeout, inodeStr;
                if (!(iss >> sl >> local >> remote >> st >> txrx >> trtm >> retr >> uid >> timeout >> inodeStr)) {
                    continue;
                }
                const auto colon = local.find(':');
                if (colon == std::string::npos) continue;
                char ipBuf[INET6_ADDRSTRLEN] = {};
                const std::string ipHex = local.substr(0, colon);
                const std::string portHex = local.substr(colon + 1);
                if (ipv6 ? !parseHexIpv6(ipHex, ipBuf, sizeof(ipBuf))
                         : !parseHexIpv4(ipHex, ipBuf, sizeof(ipBuf))) {
                    continue;
                }
                const uint16_t port = static_cast<uint16_t>(std::strtoul(portHex.c_str(), nullptr, 16));
                const uint64_t inode = std::strtoull(inodeStr.c_str(), nullptr, 10);
                if (inode == 0) continue; // TIME_WAIT, orphans, etc.
                out.push_back({ipBuf, port, protocol, inode});
            }
        }

        // Walk every /proc/<pid>/fd and collect socket inode -> owning PID.
        // Requires CAP_SYS_PTRACE (or matching uid) to see other users' fds; we
        // silently skip what we cannot read, matching Windows' "needs admin for
        // cross-user resolution" behavior.
        std::unordered_map<uint64_t, uint32_t> buildInodeToPidMap() {
            std::unordered_map<uint64_t, uint32_t> result;
            DIR* proc = opendir("/proc");
            if (!proc) return result;

            while (dirent* entry = readdir(proc)) {
                const char* name = entry->d_name;
                bool allDigits = name[0] != '\0';
                for (const char* p = name; *p; ++p) {
                    if (*p < '0' || *p > '9') { allDigits = false; break; }
                }
                if (!allDigits) continue;

                const uint32_t pid = static_cast<uint32_t>(std::strtoul(name, nullptr, 10));
                std::string fdPath = std::string("/proc/") + name + "/fd";
                DIR* fd = opendir(fdPath.c_str());
                if (!fd) continue;

                while (dirent* fdEntry = readdir(fd)) {
                    if (fdEntry->d_name[0] == '.') continue;
                    std::string linkPath = fdPath + "/" + fdEntry->d_name;
                    char target[256] = {};
                    ssize_t len = readlink(linkPath.c_str(), target, sizeof(target) - 1);
                    if (len <= 0) continue;
                    target[len] = '\0';
                    if (std::strncmp(target, "socket:[", 8) != 0) continue;
                    const uint64_t inode = std::strtoull(target + 8, nullptr, 10);
                    if (inode != 0) result[inode] = pid;
                }
                closedir(fd);
            }
            closedir(proc);
            return result;
        }

        std::string readProcessName(uint32_t pid) {
            // /proc/<pid>/comm is kernel-truncated to TASK_COMM_LEN (16 chars
            // including NUL) but universally readable without ptrace caps,
            // unlike /proc/<pid>/exe. Good enough for the App column.
            std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
            if (!f) return {};
            std::string name;
            std::getline(f, name);
            return name;
        }
    }

    void ProcessResolver::refreshLocalAddresses() {
        m_localIps.clear();
        collectInterfaceAddresses(m_localIps);
        m_localsLoaded = true;
    }

    std::string ProcessResolver::findOrResolvePidName(uint32_t pid) {
        if (auto it = m_pidToName.find(pid); it != m_pidToName.end()) return it->second;
        std::string name = readProcessName(pid);
        m_pidToName.emplace(pid, name);
        return name;
    }

    void ProcessResolver::refreshTables() {
        m_endpointToPid.clear();
        m_lastRefresh = std::chrono::steady_clock::now();

        std::vector<SocketEntry> sockets;
        appendProcNetTable(sockets, "/proc/net/tcp",  "TCP", false);
        appendProcNetTable(sockets, "/proc/net/tcp6", "TCP", true);
        appendProcNetTable(sockets, "/proc/net/udp",  "UDP", false);
        appendProcNetTable(sockets, "/proc/net/udp6", "UDP", true);
        if (sockets.empty()) return;

        const auto inodeToPid = buildInodeToPidMap();

        std::unordered_set<uint32_t> seenPids;
        for (const auto& s : sockets) {
            const auto it = inodeToPid.find(s.inode);
            if (it == inodeToPid.end()) continue;
            m_endpointToPid[Endpoint{s.ip, s.port, s.protocol}] = it->second;
            seenPids.insert(it->second);
        }
        for (uint32_t pid : seenPids) findOrResolvePidName(pid);
    }

#elif defined(__APPLE__)

    namespace {
        std::string readMacProcessName(uint32_t pid) {
            // proc_pidpath gives the full executable path; we report the
            // basename (matches the Windows convention of "firefox" rather
            // than "C:/.../firefox.exe").
            char path[PROC_PIDPATHINFO_MAXSIZE] = {};
            if (proc_pidpath(static_cast<int>(pid), path, sizeof(path)) <= 0) return {};
            std::string s(path);
            if (const auto pos = s.find_last_of('/'); pos != std::string::npos) {
                s = s.substr(pos + 1);
            }
            return s;
        }

        // Extract local IP + port from a socket_fdinfo block, returning empty
        // strings when the socket isn't a TCP/UDP IPv4/IPv6 endpoint.
        bool extractEndpoint(const socket_fdinfo& info,
                             std::string& outIp, uint16_t& outPort, std::string& outProtocol) {
            const int kind = info.psi.soi_kind;
            const int protocol = info.psi.soi_protocol;
            const in_sockinfo* ini = nullptr;
            if (kind == SOCKINFO_TCP) {
                ini = &info.psi.soi_proto.pri_tcp.tcpsi_ini;
                outProtocol = "TCP";
            } else if (kind == SOCKINFO_IN && protocol == IPPROTO_UDP) {
                ini = &info.psi.soi_proto.pri_in;
                outProtocol = "UDP";
            } else {
                return false;
            }

            const int family = info.psi.soi_family;
            char ipBuf[INET6_ADDRSTRLEN] = {};
            if (family == AF_INET) {
                if (!inet_ntop(AF_INET, &ini->insi_laddr.ina_46.i46a_addr4, ipBuf, sizeof(ipBuf))) {
                    return false;
                }
            } else if (family == AF_INET6) {
                if (!inet_ntop(AF_INET6, &ini->insi_laddr.ina_6, ipBuf, sizeof(ipBuf))) {
                    return false;
                }
            } else {
                return false;
            }

            outPort = ntohs(static_cast<uint16_t>(ini->insi_lport));
            outIp = ipBuf;
            return outPort != 0 && !outIp.empty();
        }
    }

    void ProcessResolver::refreshLocalAddresses() {
        m_localIps.clear();
        collectInterfaceAddresses(m_localIps);
        m_localsLoaded = true;
    }

    std::string ProcessResolver::findOrResolvePidName(uint32_t pid) {
        if (auto it = m_pidToName.find(pid); it != m_pidToName.end()) return it->second;
        std::string name = readMacProcessName(pid);
        m_pidToName.emplace(pid, name);
        return name;
    }

    void ProcessResolver::refreshTables() {
        m_endpointToPid.clear();
        m_lastRefresh = std::chrono::steady_clock::now();

        int pidsByteSize = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
        if (pidsByteSize <= 0) return;
        std::vector<pid_t> pids(static_cast<size_t>(pidsByteSize) / sizeof(pid_t) + 16);
        pidsByteSize = proc_listpids(PROC_ALL_PIDS, 0, pids.data(),
                                     static_cast<int>(pids.size() * sizeof(pid_t)));
        if (pidsByteSize <= 0) return;
        const int pidCount = pidsByteSize / static_cast<int>(sizeof(pid_t));

        std::unordered_set<uint32_t> seenPids;

        for (int i = 0; i < pidCount; ++i) {
            const pid_t pid = pids[i];
            if (pid == 0) continue;

            int fdsByteSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
            if (fdsByteSize <= 0) continue;
            std::vector<proc_fdinfo> fds(static_cast<size_t>(fdsByteSize) / sizeof(proc_fdinfo) + 8);
            fdsByteSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(),
                                       static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
            if (fdsByteSize <= 0) continue;
            const int fdCount = fdsByteSize / static_cast<int>(sizeof(proc_fdinfo));

            for (int j = 0; j < fdCount; ++j) {
                if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
                socket_fdinfo info{};
                const int got = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO,
                                               &info, sizeof(info));
                if (got < static_cast<int>(sizeof(info))) continue;

                std::string ip, protocol;
                uint16_t port = 0;
                if (!extractEndpoint(info, ip, port, protocol)) continue;

                m_endpointToPid[Endpoint{ip, port, protocol}] = static_cast<uint32_t>(pid);
                seenPids.insert(static_cast<uint32_t>(pid));
            }
        }

        for (uint32_t pid : seenPids) findOrResolvePidName(pid);
    }

#endif

#if !defined(_WIN32) && !defined(__linux__) && !defined(__APPLE__)
    // Unknown platform fallback: process resolution is disabled but the
    // class still compiles so the rest of the app builds.
    void ProcessResolver::refreshLocalAddresses() { m_localsLoaded = true; }
    void ProcessResolver::refreshTables() {
        m_lastRefresh = std::chrono::steady_clock::now();
    }
    std::string ProcessResolver::findOrResolvePidName(uint32_t) { return {}; }
#endif

} // namespace core
