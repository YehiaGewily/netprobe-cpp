#include "core/FlowAggregator.hpp"

#include <algorithm>
#include <functional>
#include <tuple>

namespace core {
    namespace {
        constexpr int64_t oneSecondInMicroseconds = 1'000'000;

        bool isLikelyServerPort(uint16_t port) {
            switch (port) {
            case 1194:  // OpenVPN
            case 1433:  // MSSQL
            case 3306:  // MySQL
            case 3478:  // STUN
            case 5222:  // XMPP
            case 5432:  // PostgreSQL
            case 5900:  // VNC
            case 6379:  // Redis
            case 6443:  // Kubernetes API
            case 8080:
            case 8443:
            case 9092:  // Kafka
            case 9200:  // Elasticsearch
            case 27017: // MongoDB
            case 51820: // WireGuard
                return true;
            default:
                return port > 0 && port <= 1024;
            }
        }
    }

    size_t FlowAggregator::FlowKeyHash::operator()(const FlowKey& key) const noexcept {
        size_t hash = std::hash<std::string>{}(key.srcIP);
        const auto mix = [&hash](size_t value) {
            hash ^= value + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        };
        mix(std::hash<std::string>{}(key.dstIP));
        mix(std::hash<uint16_t>{}(key.srcPort));
        mix(std::hash<uint16_t>{}(key.dstPort));
        mix(std::hash<std::string>{}(key.protocol));
        return hash;
    }

    std::optional<FlowKey> FlowAggregator::keyFor(const ParsedPacket& packet) {
        if (packet.srcIP.empty() || packet.dstIP.empty()
            || (packet.protocol != "TCP" && packet.protocol != "UDP")) {
            return std::nullopt;
        }

        const bool srcIsServer = isLikelyServerPort(packet.srcPort) && !isLikelyServerPort(packet.dstPort);
        const bool dstIsServer = isLikelyServerPort(packet.dstPort) && !isLikelyServerPort(packet.srcPort);

        const auto forward = [&] {
            return FlowKey{packet.srcIP, packet.dstIP, packet.srcPort, packet.dstPort, packet.protocol};
        };
        const auto reversed = [&] {
            return FlowKey{packet.dstIP, packet.srcIP, packet.dstPort, packet.srcPort, packet.protocol};
        };

        if (srcIsServer) return reversed();
        if (dstIsServer) return forward();

        // Neither endpoint looks like a server — peer-to-peer media, BitTorrent,
        // game traffic. Order the two endpoints deterministically so that both
        // directions hash to the same flow instead of appearing as two.
        return std::tie(packet.srcIP, packet.srcPort) <= std::tie(packet.dstIP, packet.dstPort)
            ? forward()
            : reversed();
    }

    bool FlowAggregator::matches(const ParsedPacket& packet, const FlowKey& key) {
        const auto packetKey = keyFor(packet);
        return packetKey && *packetKey == key;
    }

    bool FlowAggregator::isDownstream(const ParsedPacket& packet, const FlowKey& key) {
        return packet.srcIP == key.dstIP && packet.srcPort == key.dstPort;
    }

    void FlowAggregator::update(const ParsedPacket& packet, const std::string& hostname,
                                const std::string& process) {
        const auto key = keyFor(packet);
        if (!key) return;

        auto [entry, inserted] = m_flows.try_emplace(*key);
        FlowState& state = entry->second;
        if (inserted) {
            state.flow.key = *key;
            state.flow.firstSeen = packet.timestamp;
        }

        state.flow.lastSeen = packet.timestamp;
        ++state.flow.packets;
        const bool downstream = isDownstream(packet, *key);
        if (downstream) {
            state.flow.bytesDown += packet.length;
        } else {
            state.flow.bytesUp += packet.length;
        }
        if (packet.encryptedTunnel) state.flow.encryptedTunnel = true;

        // Initial-RTT tracking: outgoing SYN (no ACK) starts the timer,
        // matching SYN-ACK from the server stops it. Only record once per
        // flow so a SYN retransmit doesn't move the goalposts.
        if (packet.protocol == "TCP" && state.flow.initialRttMicroseconds == 0) {
            if (packet.tcpSyn && !packet.tcpAck && !downstream && !state.synSeen) {
                state.synTimestamp = packet.timestamp;
                state.synSeen = true;
            } else if (packet.tcpSyn && packet.tcpAck && downstream && state.synSeen) {
                const int64_t delta = packet.timestamp - state.synTimestamp;
                if (delta > 0) state.flow.initialRttMicroseconds = delta;
            }
        }

        // Delivery problems, judged per direction against the highest sequence
        // number seen so far. Only data-bearing segments participate: a bare
        // ACK carries no bytes and repeats the sequence number of the next
        // byte it expects, so counting them would report constant duplicates.
        //
        // All comparisons go through a signed 32-bit difference, which is
        // RFC 1982 serial arithmetic — the only way these stay correct when a
        // long-lived stream wraps past 2^32.
        if (packet.protocol == "TCP" && packet.payloadLength > 0) {
            DirectionSequence& sequence =
                downstream ? state.downSequence : state.upSequence;
            uint64_t& retransmissions =
                downstream ? state.flow.retransmissionsDown : state.flow.retransmissionsUp;
            uint64_t& outOfOrder =
                downstream ? state.flow.outOfOrderDown : state.flow.outOfOrderUp;

            const uint32_t segmentEnd =
                packet.tcpSeq + static_cast<uint32_t>(packet.payloadLength);

            if (!sequence.valid) {
                // First data we have seen in this direction establishes the
                // baseline; a flow that began before the capture started must
                // not be reported as one giant reordering.
                sequence.nextExpected = segmentEnd;
                sequence.valid = true;
            } else {
                const int32_t offsetFromExpected =
                    static_cast<int32_t>(packet.tcpSeq - sequence.nextExpected);

                if (offsetFromExpected == 0) {
                    sequence.nextExpected = segmentEnd;
                } else if (offsetFromExpected < 0) {
                    // Starts in territory already covered: a retransmission,
                    // whole or partial.
                    ++retransmissions;
                    if (static_cast<int32_t>(segmentEnd - sequence.nextExpected) > 0) {
                        sequence.nextExpected = segmentEnd; // partial overlap carried new bytes
                    }
                } else {
                    // Skips ahead of what we expected, so something earlier is
                    // missing or reordered. When the gap is filled later that
                    // segment lands in the branch above, which is why a single
                    // reordering shows as one of each.
                    ++outOfOrder;
                    sequence.nextExpected = segmentEnd;
                }
            }
        }

        // A reset ends the byte stream; sequence numbers after it belong to a
        // new connection that may reuse this address/port pair.
        if (packet.tcpRst) {
            state.upSequence = {};
            state.downSequence = {};
        }

        if (!hostname.empty()) state.flow.hostname = hostname;
        if (!packet.sni.empty()) state.flow.hostname = packet.sni;
        else if (!packet.hostname.empty()) state.flow.hostname = packet.hostname;
        if (!packet.service.empty()) state.flow.service = packet.service;
        // Keep the first non-empty resolution: the owning process is stable for
        // a flow's lifetime, and the socket may close before the flow ages out.
        if (state.flow.process.empty() && !process.empty()) state.flow.process = process;

        state.recentTraffic.push_back({packet.timestamp, packet.length});
        const int64_t cutoff = packet.timestamp - oneSecondInMicroseconds;
        while (!state.recentTraffic.empty() && state.recentTraffic.front().timestamp < cutoff) {
            state.recentTraffic.pop_front();
        }
    }

    void FlowAggregator::setHostnameForAddress(const std::string& ip, const std::string& hostname) {
        if (ip.empty() || hostname.empty()) return;
        // Either endpoint may be the one that was just resolved: for ordinary
        // traffic that is the destination, but mDNS and PTR answers name devices
        // on the local network that appear as the source of inbound flows.
        for (auto& [key, state] : m_flows) {
            if (key.dstIP == ip || key.srcIP == ip) state.flow.hostname = hostname;
        }
    }

    std::vector<Flow> FlowAggregator::snapshot(int64_t nowMicroseconds) const {
        std::vector<Flow> flows;
        flows.reserve(m_flows.size());
        const int64_t cutoff = nowMicroseconds - oneSecondInMicroseconds;

        for (const auto& [key, state] : m_flows) {
            Flow flow = state.flow;
            uint64_t bytesInWindow = 0;
            for (const auto& sample : state.recentTraffic) {
                if (sample.timestamp >= cutoff && sample.timestamp <= nowMicroseconds) {
                    bytesInWindow += sample.bytes;
                }
            }
            flow.rateBytesPerSecond = static_cast<double>(bytesInWindow);
            flows.push_back(std::move(flow));
        }
        return flows;
    }

    void FlowAggregator::clear() {
        m_flows.clear();
    }

} // namespace core
