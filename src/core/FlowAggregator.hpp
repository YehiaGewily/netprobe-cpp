#pragma once

#include "core/ParsedPacket.hpp"

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {

    struct FlowKey {
        std::string srcIP;
        std::string dstIP;
        uint16_t dstPort = 0;
        std::string protocol;

        bool operator==(const FlowKey& other) const = default;
    };

    struct Flow {
        FlowKey key;
        uint64_t bytesUp = 0;
        uint64_t bytesDown = 0;
        uint64_t packets = 0;
        int64_t firstSeen = 0;
        int64_t lastSeen = 0;
        std::string hostname;
        std::string service;
        double rateBytesPerSecond = 0.0;
    };

    class FlowAggregator {
    public:
        // Returns no key for packets that do not describe an IP transport flow.
        static std::optional<FlowKey> keyFor(const ParsedPacket& packet);
        static bool matches(const ParsedPacket& packet, const FlowKey& key);

        void update(const ParsedPacket& packet, const std::string& hostname = {});
        void setHostnameForAddress(const std::string& ip, const std::string& hostname);
        std::vector<Flow> snapshot(int64_t nowMicroseconds) const;
        void clear();

    private:
        struct FlowKeyHash {
            size_t operator()(const FlowKey& key) const noexcept;
        };

        struct TrafficSample {
            int64_t timestamp;
            uint32_t bytes;
        };

        struct FlowState {
            Flow flow;
            std::deque<TrafficSample> recentTraffic;
        };

        std::unordered_map<FlowKey, FlowState, FlowKeyHash> m_flows;
    };

} // namespace core
