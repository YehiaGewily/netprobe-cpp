#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace core {

    class HostnameCache {
    public:
        void store(const std::string& ip, const std::string& hostname) {
            if (ip.empty() || hostname.empty()) return;
            std::lock_guard<std::mutex> lock(m_mutex);
            m_hostnames[ip] = hostname;
        }

        std::optional<std::string> lookup(const std::string& ip) const {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto entry = m_hostnames.find(ip);
            return entry == m_hostnames.end() ? std::nullopt : std::optional<std::string>{entry->second};
        }

        void clear() {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_hostnames.clear();
        }

    private:
        std::unordered_map<std::string, std::string> m_hostnames;
        mutable std::mutex m_mutex;
    };

} // namespace core
