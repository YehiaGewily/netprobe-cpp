#pragma once

#include "core/QuicParser.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {

    // Reassembles a QUIC ClientHello that spans several Initial packets.
    //
    // QUIC's minimum datagram is 1200 bytes, and a ClientHello carrying a
    // post-quantum key share exceeds that — so the CRYPTO stream arrives split
    // across two or more Initials. Each is independently decryptable (the keys
    // come from the Destination Connection ID, which the client repeats), but
    // the TLS message only parses once the fragments are stitched together.
    //
    // Keyed by DCID, which is stable across the client's first flight.
    class QuicTracker {
    public:
        // Feeds one UDP payload that looked like a QUIC long header. Returns the
        // SNI on the packet that completes the ClientHello.
        std::optional<std::string> feed(const uint8_t* payload, size_t length,
            int64_t timestampMicroseconds);

        void clear();
        size_t trackedConnectionCount() const { return m_connections.size(); }

    private:
        static constexpr size_t kMaxStreamBytes = size_t{64} * 1024;
        static constexpr int64_t kConnectionTimeoutMicroseconds = 10'000'000;
        static constexpr size_t kMaxTrackedConnections = 1'024;

        struct Connection {
            std::vector<uint8_t> stream;  // TLS handshake bytes, indexed by offset
            std::vector<bool> present;    // which of those bytes have arrived
            int64_t lastSeen = 0;
        };

        struct ConnectionIdHash {
            size_t operator()(const std::vector<uint8_t>& id) const noexcept;
        };

        // Number of bytes available contiguously from offset 0.
        static size_t contiguousPrefix(const Connection& connection);
        void expireStale(int64_t now);

        std::unordered_map<std::vector<uint8_t>, Connection, ConnectionIdHash> m_connections;
    };

} // namespace core
