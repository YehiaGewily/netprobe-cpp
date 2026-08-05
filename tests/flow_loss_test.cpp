#include "core/FlowAggregator.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

// Retransmission and out-of-order accounting. The sequence-space arithmetic
// here is the kind that looks obviously correct and is not: these pin the
// wraparound and partial-overlap cases that a plain integer comparison gets
// wrong only after a stream has moved four gigabytes.
namespace {

    constexpr int64_t kBaseTimestamp = 1'700'000'000'000'000;

    core::ParsedPacket makeSegment(uint32_t sequence, uint32_t payloadLength,
        bool fromClient = true, int64_t timestamp = kBaseTimestamp) {
        core::ParsedPacket packet;
        packet.protocol = "TCP";
        packet.timestamp = timestamp;
        packet.srcIP = fromClient ? "192.168.1.10" : "93.184.216.34";
        packet.dstIP = fromClient ? "93.184.216.34" : "192.168.1.10";
        packet.srcPort = fromClient ? 50000 : 443;
        packet.dstPort = fromClient ? 443 : 50000;
        packet.tcpSeq = sequence;
        packet.tcpAck = true;
        packet.payloadOffset = 54;
        packet.payloadLength = payloadLength;
        packet.length = 54 + payloadLength;
        return packet;
    }

    core::Flow onlyFlow(const core::FlowAggregator& aggregator) {
        const auto flows = aggregator.snapshot(kBaseTimestamp + 1'000'000);
        EXPECT_EQ(flows.size(), 1u);
        return flows.empty() ? core::Flow{} : flows.front();
    }

} // namespace

TEST(FlowLossTest, InOrderStreamReportsNoProblems) {
    core::FlowAggregator aggregator;
    aggregator.update(makeSegment(1000, 100));
    aggregator.update(makeSegment(1100, 100));
    aggregator.update(makeSegment(1200, 100));

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 0u);
    EXPECT_EQ(flow.outOfOrderUp, 0u);
    EXPECT_EQ(flow.packets, 3u);
}

TEST(FlowLossTest, ExactDuplicateCountsAsRetransmission) {
    core::FlowAggregator aggregator;
    aggregator.update(makeSegment(1000, 100));
    aggregator.update(makeSegment(1100, 100));
    aggregator.update(makeSegment(1100, 100)); // the wire repeats itself

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 1u);
    EXPECT_EQ(flow.outOfOrderUp, 0u);
}

TEST(FlowLossTest, PartialOverlapCountsOnceAndStillAdvances) {
    core::FlowAggregator aggregator;
    aggregator.update(makeSegment(1000, 200)); // covers 1000..1200
    // Rewinds 100 bytes but carries 100 genuinely new ones (1100..1300).
    aggregator.update(makeSegment(1100, 200));
    // The next in-order segment must not itself look like a problem, which it
    // would if the overlap had failed to advance the expected sequence.
    aggregator.update(makeSegment(1300, 100));

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 1u);
    EXPECT_EQ(flow.outOfOrderUp, 0u);
}

TEST(FlowLossTest, GapThenFillCountsOneOutOfOrderAndOneRetransmission) {
    core::FlowAggregator aggregator;
    aggregator.update(makeSegment(1000, 100)); // A
    aggregator.update(makeSegment(1200, 100)); // C, skipping B
    aggregator.update(makeSegment(1100, 100)); // B arrives late

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.outOfOrderUp, 1u);      // observed at C
    EXPECT_EQ(flow.retransmissionsUp, 1u); // B lands behind the high-water mark
}

TEST(FlowLossTest, SequenceWraparoundIsNotMistakenForLoss) {
    core::FlowAggregator aggregator;
    // Runs off the end of the 32-bit sequence space and back around. Every
    // segment is strictly in order, so nothing may be reported.
    aggregator.update(makeSegment(0xFFFFFF00u, 100)); // ends at 0xFFFFFF64
    aggregator.update(makeSegment(0xFFFFFF64u, 200)); // ends at 0x0000002C
    aggregator.update(makeSegment(0x0000002Cu, 100)); // ends at 0x00000090
    aggregator.update(makeSegment(0x00000090u, 100));

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 0u)
        << "wraparound was misread as a retransmission";
    EXPECT_EQ(flow.outOfOrderUp, 0u)
        << "wraparound was misread as reordering";
}

TEST(FlowLossTest, RetransmissionAcrossWraparoundIsStillDetected) {
    core::FlowAggregator aggregator;
    aggregator.update(makeSegment(0xFFFFFF00u, 100));
    aggregator.update(makeSegment(0xFFFFFF64u, 200)); // wraps to 0x2C
    aggregator.update(makeSegment(0xFFFFFF64u, 200)); // repeat of the wrapping segment

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 1u);
    EXPECT_EQ(flow.outOfOrderUp, 0u);
}

TEST(FlowLossTest, DirectionsAreCountedIndependently) {
    core::FlowAggregator aggregator;
    aggregator.update(makeSegment(1000, 100, /*fromClient=*/false));
    aggregator.update(makeSegment(1100, 100, /*fromClient=*/false));
    aggregator.update(makeSegment(1100, 100, /*fromClient=*/false)); // server retransmits
    aggregator.update(makeSegment(500, 50, /*fromClient=*/true));
    aggregator.update(makeSegment(550, 50, /*fromClient=*/true));

    const auto flow = onlyFlow(aggregator);
    // The flow key is canonical, so establish which side is which rather than
    // assuming the client ended up as `src`.
    const bool clientIsSource = flow.key.srcPort == 50000;
    const uint64_t serverRetransmissions =
        clientIsSource ? flow.retransmissionsDown : flow.retransmissionsUp;
    const uint64_t clientRetransmissions =
        clientIsSource ? flow.retransmissionsUp : flow.retransmissionsDown;

    EXPECT_EQ(serverRetransmissions, 1u);
    EXPECT_EQ(clientRetransmissions, 0u) << "a server retransmit leaked into the client direction";
}

TEST(FlowLossTest, PureAcksAndFlowsStartingMidStreamReportNothing) {
    core::FlowAggregator aggregator;
    // A capture that began after the connection did: the first segment we see
    // sits at an arbitrary offset and must only establish the baseline.
    aggregator.update(makeSegment(987'654'321u, 100));
    // Bare ACKs carry no payload and repeat sequence numbers by design.
    core::ParsedPacket bareAck = makeSegment(987'654'421u, 0);
    aggregator.update(bareAck);
    aggregator.update(bareAck);
    aggregator.update(makeSegment(987'654'421u, 100));

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 0u);
    EXPECT_EQ(flow.outOfOrderUp, 0u);
}

TEST(FlowLossTest, ResetClearsSequenceTrackingForAReusedPortPair) {
    core::FlowAggregator aggregator;
    aggregator.update(makeSegment(1000, 100));
    aggregator.update(makeSegment(1100, 100));

    core::ParsedPacket reset = makeSegment(1200, 0);
    reset.tcpRst = true;
    aggregator.update(reset);

    // A new connection reusing the same ports starts a fresh sequence space;
    // without the reset this would look like a huge backwards jump.
    aggregator.update(makeSegment(50, 100));
    aggregator.update(makeSegment(150, 100));

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 0u);
    EXPECT_EQ(flow.outOfOrderUp, 0u);
}

TEST(FlowLossTest, NonTcpTrafficNeverReportsLoss) {
    core::FlowAggregator aggregator;
    core::ParsedPacket udp;
    udp.protocol = "UDP";
    udp.timestamp = kBaseTimestamp;
    udp.srcIP = "192.168.1.10";
    udp.dstIP = "1.1.1.1";
    udp.srcPort = 53000;
    udp.dstPort = 53;
    udp.tcpSeq = 999'999; // stale field; must be ignored for UDP
    udp.payloadLength = 40;
    udp.length = 82;

    aggregator.update(udp);
    aggregator.update(udp);

    const auto flow = onlyFlow(aggregator);
    EXPECT_EQ(flow.retransmissionsUp, 0u);
    EXPECT_EQ(flow.retransmissionsDown, 0u);
    EXPECT_EQ(flow.outOfOrderUp, 0u);
}
