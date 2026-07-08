#include "core/TlsReassembler.hpp"
#include "core/ProtocolParser.hpp"

#include <algorithm>
#include <functional>

namespace core {

    size_t TlsReassembler::StreamKeyHash::operator()(const StreamKey& key) const noexcept {
        size_t hash = std::hash<std::string>{}(key.srcIP);
        hash ^= std::hash<std::string>{}(key.dstIP) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= std::hash<uint16_t>{}(key.srcPort) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= std::hash<uint16_t>{}(key.dstPort) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        return hash;
    }

    void TlsReassembler::expireStale(int64_t now) {
        for (auto it = m_streams.begin(); it != m_streams.end();) {
            it = (now - it->second.lastSeen > kStreamTimeoutMicroseconds)
                ? m_streams.erase(it)
                : std::next(it);
        }
    }

    std::optional<std::string> TlsReassembler::feed(const ParsedPacket& packet,
        const uint8_t* payload, size_t length) {

        if (packet.protocol != "TCP" || payload == nullptr || length == 0) return std::nullopt;

        const StreamKey key{packet.srcIP, packet.dstIP, packet.srcPort, packet.dstPort};
        auto existing = m_streams.find(key);

        if (existing == m_streams.end()) {
            // Only start tracking on the segment that opens a handshake record.
            if (!ProtocolParser::looksLikeTlsHandshake(payload, length)) return std::nullopt;

            // A complete ClientHello in one segment never needs buffering — the
            // parser already handled it. Only take over when it is truncated.
            const size_t recordLength = (static_cast<size_t>(payload[3]) << 8) | payload[4];
            const size_t needed = 5 + recordLength;
            if (needed <= length) return std::nullopt;
            if (needed > kMaxBufferedBytes) return std::nullopt;

            if (m_streams.size() >= kMaxTrackedStreams) {
                expireStale(packet.timestamp);
                if (m_streams.size() >= kMaxTrackedStreams) return std::nullopt;
            }

            Stream stream;
            stream.buffer.assign(payload, payload + length);
            stream.nextSeq = packet.tcpSeq + static_cast<uint32_t>(length);
            stream.needed = needed;
            stream.lastSeen = packet.timestamp;
            m_streams.emplace(key, std::move(stream));
            return std::nullopt;
        }

        Stream& stream = existing->second;
        stream.lastSeen = packet.timestamp;

        // Only in-order continuations. A retransmit of the segment we already
        // hold is harmless to ignore; a genuine gap means we would be splicing
        // bytes at the wrong offset, so give up on the stream.
        if (packet.tcpSeq != stream.nextSeq) {
            if (packet.tcpSeq + static_cast<uint32_t>(length) == stream.nextSeq) {
                return std::nullopt; // duplicate of the previous segment
            }
            m_streams.erase(existing);
            return std::nullopt;
        }

        if (stream.buffer.size() + length > kMaxBufferedBytes) {
            m_streams.erase(existing);
            return std::nullopt;
        }

        stream.buffer.insert(stream.buffer.end(), payload, payload + length);
        stream.nextSeq += static_cast<uint32_t>(length);

        if (stream.buffer.size() < stream.needed) return std::nullopt;

        std::string sni;
        const bool parsed = ProtocolParser::parseTlsClientHello(
            stream.buffer.data(), stream.buffer.size(), sni);
        m_streams.erase(existing);

        if (parsed && !sni.empty()) return sni;
        return std::nullopt;
    }

    void TlsReassembler::clear() {
        m_streams.clear();
    }

} // namespace core
