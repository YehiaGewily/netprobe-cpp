#include "PacketBuilders.hpp"

#include "core/AnalysisSession.hpp"
#include "core/DNSParser.hpp"
#include "core/PacketData.hpp"
#include "core/ProtocolParser.hpp"
#include "core/QuicParser.hpp"
#include "core/QuicTracker.hpp"
#include "core/TlsReassembler.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

// Deterministic adversarial inputs: headers that lie about their own length,
// chains that run off the end of the buffer, counts larger than the data
// present. Fuzzing finds these shapes eventually; checking them in as named
// cases means a regression is reported as a failing test with a name rather
// than as a crash artifact from a 60-second CI fuzz run.
//
// Under the ASan/UBSan CI job these also assert the absence of out-of-bounds
// reads, which is the failure mode that matters most here — a parser can walk
// off the end of a packet and still return a plausible-looking result.
namespace {

    using namespace test;

    core::PacketData toPacketData(const std::vector<uint8_t>& bytes) {
        // A zero-length capture still has to be representable: PacketData
        // takes a pointer, and passing data() of an empty vector is fine only
        // because the length is zero.
        static const uint8_t placeholder = 0;
        return core::PacketData(1'700'000'000'000'000,
            static_cast<uint32_t>(bytes.size()),
            static_cast<uint32_t>(bytes.size()),
            bytes.empty() ? &placeholder : bytes.data());
    }

    // Everything a malformed packet is allowed to produce. The point is not
    // that parsing succeeds, but that failure is expressed as absent or
    // clearly-marked fields rather than as garbage that reads as real.
    // Asserts the specific degraded result a fixture declares. This is the
    // half that catches a parser quietly starting to invent answers; the
    // generic sanity checks below only catch it going off the rails.
    void expectPinnedOutcome(const core::ParsedPacket& parsed,
        const malformed::Case& testCase) {
        if (!testCase.expectedProtocol.empty()) {
            EXPECT_EQ(parsed.protocol, testCase.expectedProtocol)
                << testCase.name << ": parsed as a different transport than expected";
        }
        if (testCase.expectNoPayload) {
            EXPECT_EQ(parsed.payloadLength, 0u)
                << testCase.name << ": located a payload that is not there";
        }
        if (testCase.expectNoSni) {
            // An SNI here would be fabricated from bytes that do not encode
            // one — and it would be shown to the user as fact.
            EXPECT_TRUE(parsed.sni.empty())
                << testCase.name << ": invented an SNI (" << parsed.sni << ")";
        }
    }

    void expectDegradedButSane(const core::ParsedPacket& parsed,
        const std::vector<uint8_t>& bytes, const std::string& name) {
        // A payload window must never point outside the captured bytes.
        if (parsed.payloadLength > 0) {
            EXPECT_LE(parsed.payloadOffset, bytes.size()) << name;
            EXPECT_LE(parsed.payloadOffset + parsed.payloadLength, bytes.size())
                << name << ": payload window runs past the captured data";
        }
        // Addresses are either empty or plausible text, never raw bytes.
        for (const std::string& address : {parsed.srcIP, parsed.dstIP}) {
            EXPECT_LT(address.size(), 64u) << name;
            EXPECT_EQ(address.find('\0'), std::string::npos)
                << name << ": address contains a NUL byte";
        }
        // A hostname recovered from a malformed packet is the most dangerous
        // field to get wrong, since it is shown to the user as fact.
        EXPECT_LT(parsed.sni.size(), 1024u) << name;
        EXPECT_LT(parsed.hostname.size(), 1024u) << name;
    }

} // namespace

TEST(MalformedPacketTest, ProtocolParserSurvivesEveryAdversarialCase) {
    const auto cases = malformed::allCases();
    ASSERT_FALSE(cases.empty());

    for (const auto& testCase : cases) {
        const auto raw = toPacketData(testCase.bytes);
        const auto parsed = core::ProtocolParser::parse(raw);
        expectDegradedButSane(parsed, testCase.bytes, testCase.name);
        expectPinnedOutcome(parsed, testCase);
    }
}

TEST(MalformedPacketTest, DnsParserSurvivesEveryAdversarialCase) {
    for (const auto& testCase : malformed::allCases()) {
        const auto raw = toPacketData(testCase.bytes);
        const auto parsed = core::ProtocolParser::parse(raw);

        const auto response = core::DNSParser::parseResponse(raw, parsed);
        if (!response) continue;

        // A record count in the header is a claim, not a promise; whatever
        // survives parsing must be backed by bytes that were actually there.
        EXPECT_LT(response->answers.size(), 256u) << testCase.name;
        EXPECT_LT(response->queryName.size(), 1024u) << testCase.name;
        for (const auto& answer : response->answers) {
            EXPECT_LT(answer.name.size(), 1024u) << testCase.name;
            EXPECT_LT(answer.value.size(), 1024u) << testCase.name;
        }
    }
}

TEST(MalformedPacketTest, StatefulParsersSurviveEveryAdversarialCase) {
    // The reassemblers hold state across packets, so feed the whole corpus
    // through single instances: a case that corrupts internal state shows up
    // as a later failure rather than an immediate one.
    core::TlsReassembler tlsReassembler;
    core::QuicTracker quicTracker;

    for (const auto& testCase : malformed::allCases()) {
        const auto raw = toPacketData(testCase.bytes);
        const auto parsed = core::ProtocolParser::parse(raw);

        if (parsed.payloadLength == 0 || parsed.payloadOffset >= testCase.bytes.size()) continue;

        const uint8_t* payload = testCase.bytes.data() + parsed.payloadOffset;
        const size_t payloadLength = std::min(parsed.payloadLength,
            testCase.bytes.size() - parsed.payloadOffset);

        if (parsed.protocol == "TCP") {
            const auto sni = tlsReassembler.feed(parsed, payload, payloadLength);
            if (sni) EXPECT_LT(sni->size(), 1024u) << testCase.name;
        } else if (parsed.protocol == "UDP") {
            if (core::QuicParser::looksLikeLongHeader(payload, payloadLength)) {
                const auto sni = quicTracker.feed(payload, payloadLength, parsed.timestamp);
                if (sni) EXPECT_LT(sni->size(), 1024u) << testCase.name;
            }
        }
    }

    // Malformed input must not leave half-built streams pinned forever.
    EXPECT_LT(tlsReassembler.trackedStreamCount(), 64u);
}

TEST(MalformedPacketTest, AnalysisSessionSurvivesEveryAdversarialCase) {
    // The full pipeline, including flow aggregation, on the same corpus.
    core::AnalysisSession session(/*resolveProcesses=*/false);

    for (const auto& testCase : malformed::allCases()) {
        const auto result = session.feed(toPacketData(testCase.bytes));
        expectDegradedButSane(result.parsed, testCase.bytes, testCase.name);
        EXPECT_LT(result.hostname.size(), 1024u) << testCase.name;
    }

    // Whatever flows were created must be internally consistent.
    for (const auto& flow : session.flows(1'700'000'001'000'000)) {
        EXPECT_GT(flow.packets, 0u);
        EXPECT_LE(flow.firstSeen, flow.lastSeen);
        EXPECT_LT(flow.hostname.size(), 1024u);
    }
}

TEST(MalformedPacketTest, TruncatingAValidFrameAtEveryOffsetNeverCrashes) {
    // Exhaustive rather than sampled: every prefix of a well-formed packet is
    // a packet some driver or capture file can hand us.
    const auto frame = malformed::validTcpFrame(makeTlsClientHello("prefix.example.com"));
    core::TlsReassembler reassembler;

    for (size_t length = 0; length <= frame.size(); ++length) {
        const std::vector<uint8_t> prefix(frame.begin(),
            frame.begin() + static_cast<std::ptrdiff_t>(length));
        const auto raw = toPacketData(prefix);
        const auto parsed = core::ProtocolParser::parse(raw);
        expectDegradedButSane(parsed, prefix, "prefix-length-" + std::to_string(length));

        (void)core::DNSParser::parseResponse(raw, parsed);
        if (parsed.protocol == "TCP" && parsed.payloadLength > 0
            && parsed.payloadOffset < prefix.size()) {
            (void)reassembler.feed(parsed, prefix.data() + parsed.payloadOffset,
                std::min(parsed.payloadLength, prefix.size() - parsed.payloadOffset));
        }
    }
}

TEST(MalformedPacketTest, Ipv6ExtensionChainWalkAlwaysTerminates) {
    // The walk is an unbounded `while (true)`; it is safe only because every
    // step advances at least eight bytes within a bounded buffer. If that ever
    // stops being true this test hangs instead of passing, which is the point.
    for (const auto& testCase : malformed::allCases()) {
        if (testCase.name.find("ipv6") == std::string::npos) continue;
        const auto parsed = core::ProtocolParser::parse(toPacketData(testCase.bytes));
        expectDegradedButSane(parsed, testCase.bytes, testCase.name);
    }

    // A chain built entirely of zero-length headers, filling the packet.
    std::vector<uint8_t> chain;
    for (int link = 0; link < 200; ++link) {
        chain.push_back(0); // hop-by-hop pointing at another hop-by-hop
        chain.push_back(0);
        chain.resize(chain.size() + 6, 0x00);
    }
    const auto packet = malformed::ipv6WithChain(0, chain);
    const auto parsed = core::ProtocolParser::parse(toPacketData(packet));
    expectDegradedButSane(parsed, packet, "ipv6-exhaustive-zero-length-chain");
}
