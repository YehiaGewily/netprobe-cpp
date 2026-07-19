#pragma once

#include "core/ParsedPacket.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {

    // Buffers TLS ClientHello bytes across TCP segments.
    //
    // A ClientHello used to fit comfortably in one segment. It no longer does:
    // post-quantum key shares (X25519MLKEM768, now the default in Chrome and
    // Firefox) push the message past a typical 1460-byte MSS, so a parser that
    // only ever looks at a single segment silently stops finding SNI on a
    // growing share of real traffic.
    //
    // Scope is deliberately narrow — we only track the client's first flight,
    // in order, until the record is complete. Out-of-order segments, oversized
    // records, and non-handshake streams are dropped rather than buffered.
    class TlsReassembler {
    public:
        // Feeds one TCP segment's payload. Returns the SNI on the segment that
        // completes the ClientHello, and std::nullopt otherwise.
        std::optional<std::string> feed(const ParsedPacket& packet,
            const uint8_t* payload, size_t length);

        void clear();
        size_t trackedStreamCount() const { return m_streams.size(); }

    private:
        // Beyond this a "ClientHello" is either malicious or not a ClientHello.
        static constexpr size_t kMaxBufferedBytes = size_t{64} * 1024;
        // Stop tracking a stream that has gone quiet, so a long capture does not
        // accumulate half-finished handshakes forever.
        static constexpr int64_t kStreamTimeoutMicroseconds = 30'000'000;
        static constexpr size_t kMaxTrackedStreams = 2'048;

        struct StreamKey {
            std::string srcIP;
            std::string dstIP;
            uint16_t srcPort = 0;
            uint16_t dstPort = 0;
            bool operator==(const StreamKey& other) const = default;
        };

        struct StreamKeyHash {
            size_t operator()(const StreamKey& key) const noexcept;
        };

        struct Stream {
            std::vector<uint8_t> buffer;
            uint32_t nextSeq = 0;    // TCP sequence number expected next
            size_t needed = 0;       // total record bytes required, 0 until known
            int64_t lastSeen = 0;
        };

        void expireStale(int64_t now);

        std::unordered_map<StreamKey, Stream, StreamKeyHash> m_streams;
    };

} // namespace core
