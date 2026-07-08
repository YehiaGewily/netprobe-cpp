#include "core/QuicTracker.hpp"

#include <algorithm>
#include <functional>

namespace core {

    size_t QuicTracker::ConnectionIdHash::operator()(const std::vector<uint8_t>& id) const noexcept {
        size_t hash = 1469598103934665603ull; // FNV-1a offset basis
        for (uint8_t byte : id) {
            hash ^= byte;
            hash *= 1099511628211ull;
        }
        return hash;
    }

    size_t QuicTracker::contiguousPrefix(const Connection& connection) {
        size_t count = 0;
        while (count < connection.present.size() && connection.present[count]) ++count;
        return count;
    }

    void QuicTracker::expireStale(int64_t now) {
        for (auto it = m_connections.begin(); it != m_connections.end();) {
            it = (now - it->second.lastSeen > kConnectionTimeoutMicroseconds)
                ? m_connections.erase(it)
                : std::next(it);
        }
    }

    std::optional<std::string> QuicTracker::feed(const uint8_t* payload, size_t length,
        int64_t timestampMicroseconds) {

        const auto initial = QuicParser::parseInitial(payload, length);
        if (!initial || initial->crypto.empty()) return std::nullopt;

        auto entry = m_connections.find(initial->destinationConnectionId);
        if (entry == m_connections.end()) {
            if (m_connections.size() >= kMaxTrackedConnections) {
                expireStale(timestampMicroseconds);
                if (m_connections.size() >= kMaxTrackedConnections) return std::nullopt;
            }
            entry = m_connections.emplace(initial->destinationConnectionId, Connection{}).first;
        }

        Connection& connection = entry->second;
        connection.lastSeen = timestampMicroseconds;

        for (const auto& fragment : initial->crypto) {
            const size_t end = static_cast<size_t>(fragment.offset) + fragment.data.size();
            if (end > kMaxStreamBytes) {
                m_connections.erase(entry);
                return std::nullopt;
            }
            if (connection.stream.size() < end) {
                connection.stream.resize(end, 0);
                connection.present.resize(end, false);
            }
            std::copy(fragment.data.begin(), fragment.data.end(),
                connection.stream.begin() + static_cast<std::ptrdiff_t>(fragment.offset));
            std::fill(connection.present.begin() + static_cast<std::ptrdiff_t>(fragment.offset),
                connection.present.begin() + static_cast<std::ptrdiff_t>(end), true);
        }

        // The ClientHello only parses once every byte up to its declared length
        // has arrived; until then this is cheap and simply returns nullopt.
        const size_t usable = contiguousPrefix(connection);
        if (usable < 4) return std::nullopt;

        auto sni = QuicParser::sniFromClientHello(connection.stream.data(), usable);
        if (sni) {
            m_connections.erase(entry);
            return sni;
        }
        return std::nullopt;
    }

    void QuicTracker::clear() {
        m_connections.clear();
    }

} // namespace core
