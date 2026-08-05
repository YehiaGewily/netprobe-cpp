#pragma once

#include "core/ParsedPacket.hpp"

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {

    // A flow key is canonical: both directions of the same conversation produce
    // an identical key, with `src` naming the endpoint we treat as the client.
    // Both ports are part of the key — without srcPort, two simultaneous
    // peer-to-peer conversations between the same hosts would collide.
    struct FlowKey {
        std::string srcIP;
        std::string dstIP;
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;
        std::string protocol;

        bool operator==(const FlowKey& other) const = default;
    };

    struct Flow {
        FlowKey key;
        // Traffic sent by the key's `src` endpoint (bytesUp) and by its `dst`
        // endpoint (bytesDown). For ordinary client/server traffic that reads as
        // outbound/inbound; for peer-to-peer flows the split is still correct,
        // just symmetric.
        uint64_t bytesUp = 0;
        uint64_t bytesDown = 0;
        uint64_t packets = 0;
        int64_t firstSeen = 0;
        int64_t lastSeen = 0;
        std::string hostname;
        std::string service;
        // Local process that owns this flow's socket, resolved once while the
        // connection was still live (see ProcessResolver). Empty when the flow
        // isn't local, the socket had already closed, or the lookup failed.
        std::string process;
        double rateBytesPerSecond = 0.0;
        // Initial TCP RTT, in microseconds. Computed once when both the
        // outgoing SYN and the matching SYN-ACK have been observed; 0 means
        // the flow either isn't TCP, started before the capture, or hasn't
        // reached SYN-ACK yet.
        int64_t initialRttMicroseconds = 0;
        // True when the transport is an encrypted tunnel (ESP, WireGuard,
        // OpenVPN) and the inner conversation can never be resolved.
        bool encryptedTunnel = false;

        // TCP delivery problems seen from this capture point, split by
        // direction (Up = sent by the key's `src`). Always zero for non-TCP.
        //
        // These are capture-point counts, in the same sense as Wireshark's:
        // a segment carrying bytes we have already seen is counted as a
        // retransmission, and one that skips ahead of the expected sequence
        // as out-of-order. Capturing on the sending host makes them a good
        // proxy for real loss; capturing mid-path only shows what reached
        // this vantage point.
        uint64_t retransmissionsUp = 0;
        uint64_t retransmissionsDown = 0;
        uint64_t outOfOrderUp = 0;
        uint64_t outOfOrderDown = 0;
    };

    class FlowAggregator {
    public:
        // Returns no key for packets that do not describe an IP transport flow.
        static std::optional<FlowKey> keyFor(const ParsedPacket& packet);
        static bool matches(const ParsedPacket& packet, const FlowKey& key);
        // True when the packet travels from the key's `dst` endpoint toward its
        // `src` endpoint — i.e. server to client for ordinary traffic.
        static bool isDownstream(const ParsedPacket& packet, const FlowKey& key);

        void update(const ParsedPacket& packet, const std::string& hostname = {},
                    const std::string& process = {});
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

        // Highest sequence number seen so far in one direction of a stream.
        struct DirectionSequence {
            uint32_t nextExpected = 0;
            bool valid = false; // false until the first data segment arrives
        };

        struct FlowState {
            Flow flow;
            std::deque<TrafficSample> recentTraffic;
            DirectionSequence upSequence;
            DirectionSequence downSequence;
            // Timestamps used to compute the initial three-way-handshake RTT.
            // synTimestamp is the first client→server SYN we saw; syn-ack
            // arrival in the other direction yields the RTT delta.
            int64_t synTimestamp = 0;
            bool synSeen = false;
        };

        std::unordered_map<FlowKey, FlowState, FlowKeyHash> m_flows;
    };

} // namespace core
