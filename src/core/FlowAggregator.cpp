#include "core/FlowAggregator.hpp"

#include <algorithm>
#include <functional>

namespace core {
    namespace {
        constexpr int64_t oneSecondInMicroseconds = 1'000'000;

        bool isLikelyServerPort(uint16_t port) {
            switch (port) {
            case 3306:  // MySQL
            case 3478:  // STUN
            case 5222:  // XMPP
            case 5432:  // PostgreSQL
            case 6379:  // Redis
            case 8080:
            case 8443:
            case 27017: // MongoDB
                return true;
            default:
                return port > 0 && port <= 1024;
            }
        }

        bool isServerToClient(const ParsedPacket& packet) {
            return isLikelyServerPort(packet.srcPort) && !isLikelyServerPort(packet.dstPort);
        }
    }

    size_t FlowAggregator::FlowKeyHash::operator()(const FlowKey& key) const noexcept {
        size_t hash = std::hash<std::string>{}(key.srcIP);
        hash ^= std::hash<std::string>{}(key.dstIP) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= std::hash<uint16_t>{}(key.dstPort) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= std::hash<std::string>{}(key.protocol) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        return hash;
    }

    std::optional<FlowKey> FlowAggregator::keyFor(const ParsedPacket& packet) {
        if (packet.srcIP.empty() || packet.dstIP.empty()
            || (packet.protocol != "TCP" && packet.protocol != "UDP")) {
            return std::nullopt;
        }

        if (isServerToClient(packet)) {
            return FlowKey{packet.dstIP, packet.srcIP, packet.srcPort, packet.protocol};
        }
        return FlowKey{packet.srcIP, packet.dstIP, packet.dstPort, packet.protocol};
    }

    bool FlowAggregator::matches(const ParsedPacket& packet, const FlowKey& key) {
        const auto packetKey = keyFor(packet);
        return packetKey && *packetKey == key;
    }

    void FlowAggregator::update(const ParsedPacket& packet, const std::string& hostname) {
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
        if (isServerToClient(packet)) {
            state.flow.bytesDown += packet.length;
        } else {
            state.flow.bytesUp += packet.length;
        }

        if (!hostname.empty()) state.flow.hostname = hostname;
        if (!packet.sni.empty()) state.flow.hostname = packet.sni;
        if (!packet.service.empty()) state.flow.service = packet.service;

        state.recentTraffic.push_back({packet.timestamp, packet.length});
        const int64_t cutoff = packet.timestamp - oneSecondInMicroseconds;
        while (!state.recentTraffic.empty() && state.recentTraffic.front().timestamp < cutoff) {
            state.recentTraffic.pop_front();
        }
    }

    void FlowAggregator::setHostnameForAddress(const std::string& ip, const std::string& hostname) {
        if (ip.empty() || hostname.empty()) return;
        for (auto& [key, state] : m_flows) {
            if (key.dstIP == ip) state.flow.hostname = hostname;
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
