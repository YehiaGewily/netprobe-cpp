#pragma once

#include "core/ParsedPacket.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace core {

    // Resolves the local process that owns a captured packet's connection.
    // Refreshes the OS socket tables on a fixed cadence and caches PID → name
    // so per-packet lookups remain O(1) hash hits during render.
    class ProcessResolver {
    public:
        ProcessResolver();

        // Returns the executable name (without ".exe") that owns the local endpoint
        // of the packet, or an empty string if it can't be resolved (no longer in
        // the socket table, packet didn't originate locally, lookup failed, etc.).
        std::string lookup(const ParsedPacket& packet);

    private:
        struct Endpoint {
            std::string ip;
            uint16_t port = 0;
            std::string protocol; // "TCP" / "UDP"

            bool operator==(const Endpoint& other) const = default;
        };
        struct EndpointHash {
            size_t operator()(const Endpoint& e) const noexcept;
        };

        void refreshTables();
        void refreshLocalAddresses();
        std::string findOrResolvePidName(uint32_t pid);

        std::unordered_map<Endpoint, uint32_t, EndpointHash> m_endpointToPid;
        std::unordered_map<uint32_t, std::string> m_pidToName;
        std::unordered_set<std::string> m_localIps;
        std::chrono::steady_clock::time_point m_lastRefresh{};
        bool m_localsLoaded = false;
    };

} // namespace core
