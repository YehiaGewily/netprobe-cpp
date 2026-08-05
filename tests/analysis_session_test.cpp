#include "PacketBuilders.hpp"

#include "core/AnalysisSession.hpp"
#include "core/PacketData.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

// Exercises the pipeline as a whole rather than one parser at a time: these
// pin the cross-packet behaviour (a DNS answer naming a later flow, a
// ClientHello that only yields SNI once its second segment arrives) that the
// GUI and the CLI both depend on.
namespace {

    using namespace test;

    constexpr int64_t kBaseTimestamp = 1'700'000'000'000'000;

    const std::vector<uint8_t> kClient = {192, 168, 1, 10};
    const std::vector<uint8_t> kServer = {93, 184, 216, 34};
    const std::vector<uint8_t> kResolver = {8, 8, 8, 8};

    core::PacketData toPacketData(const std::vector<uint8_t>& bytes, int64_t timestamp) {
        core::PacketData packet(timestamp, static_cast<uint32_t>(bytes.size()),
            static_cast<uint32_t>(bytes.size()), bytes.data());
        return packet;
    }

    std::vector<uint8_t> makeTcpPacket(const std::vector<uint8_t>& source,
        const std::vector<uint8_t>& destination, uint16_t sourcePort, uint16_t destinationPort,
        uint32_t sequence, uint8_t flags, const std::vector<uint8_t>& payload) {
        std::vector<uint8_t> packet;
        appendEthernetHeader(packet, 0x0800);
        appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + payload.size()), 6,
            source, destination);
        appendTcpHeader(packet, sourcePort, destinationPort, sequence, flags);
        packet.insert(packet.end(), payload.begin(), payload.end());
        return packet;
    }

    // A minimal DNS response: one question for `name`, one A answer.
    std::vector<uint8_t> makeDnsResponsePacket(const std::string& name,
        const std::vector<uint8_t>& address) {
        std::vector<uint8_t> dns;
        appendU16(dns, 0x1234); // transaction ID
        appendU16(dns, 0x8180); // standard response
        appendU16(dns, 1);      // questions
        appendU16(dns, 1);      // answers
        appendU16(dns, 0);
        appendU16(dns, 0);
        appendDnsName(dns, name);
        appendU16(dns, 1); // QTYPE A
        appendU16(dns, 1); // QCLASS IN

        appendDnsName(dns, name);
        appendU16(dns, 1);
        appendU16(dns, 1);
        appendU32BE(dns, 60);
        appendU16(dns, static_cast<uint16_t>(address.size()));
        dns.insert(dns.end(), address.begin(), address.end());

        std::vector<uint8_t> packet;
        appendEthernetHeader(packet, 0x0800);
        appendIPv4Header(packet, static_cast<uint16_t>(20 + 8 + dns.size()), 17,
            kResolver, kClient);
        appendUdpHeader(packet, 53, 53000, static_cast<uint16_t>(dns.size()));
        packet.insert(packet.end(), dns.begin(), dns.end());
        return packet;
    }

    // Process resolution walks the OS socket tables, which is meaningless for
    // synthetic packets, so every test drives the session with it disabled.
    core::AnalysisSession makeSession() { return core::AnalysisSession(false); }

} // namespace

TEST(AnalysisSessionTest, DnsAnswerNamesASubsequentFlow) {
    auto session = makeSession();

    const auto dnsPacket = makeDnsResponsePacket("www.example.com", kServer);
    session.feed(toPacketData(dnsPacket, kBaseTimestamp));

    const auto tcpPacket = makeTcpPacket(kClient, kServer, 50000, 443, 1000, 0x10, {});
    const auto analyzed = session.feed(toPacketData(tcpPacket, kBaseTimestamp + 1000));

    EXPECT_EQ(analyzed.hostname, "www.example.com");

    const auto flows = session.flows(kBaseTimestamp + 2000);
    const auto named = std::find_if(flows.begin(), flows.end(), [](const core::Flow& flow) {
        return flow.hostname == "www.example.com";
    });
    ASSERT_NE(named, flows.end()) << "DNS answer did not name the flow it resolved";
    EXPECT_EQ(named->key.protocol, "TCP");
}

TEST(AnalysisSessionTest, RecoversSniFromClientHelloSplitAcrossSegments) {
    auto session = makeSession();

    const auto clientHello = makeTlsClientHello("split.example.com");
    const size_t firstHalf = clientHello.size() / 2;

    const std::vector<uint8_t> firstPayload(clientHello.begin(),
        clientHello.begin() + static_cast<std::ptrdiff_t>(firstHalf));
    const std::vector<uint8_t> secondPayload(clientHello.begin() + static_cast<std::ptrdiff_t>(firstHalf),
        clientHello.end());

    const auto first = makeTcpPacket(kClient, kServer, 50000, 443, 1000, 0x18, firstPayload);
    const auto firstResult = session.feed(toPacketData(first, kBaseTimestamp));
    EXPECT_TRUE(firstResult.parsed.sni.empty())
        << "half a ClientHello should not yield an SNI";

    const auto second = makeTcpPacket(kClient, kServer, 50000, 443,
        static_cast<uint32_t>(1000 + firstHalf), 0x18, secondPayload);
    const auto secondResult = session.feed(toPacketData(second, kBaseTimestamp + 1000));
    EXPECT_EQ(secondResult.parsed.sni, "split.example.com");
    EXPECT_EQ(secondResult.hostname, "split.example.com");
}

TEST(AnalysisSessionTest, CountsPlaintextDnsAndClearsAllState) {
    auto session = makeSession();

    session.feed(toPacketData(makeDnsResponsePacket("www.example.com", kServer), kBaseTimestamp));
    const auto tcpPacket = makeTcpPacket(kClient, kServer, 50000, 443, 1000, 0x10, {});
    session.feed(toPacketData(tcpPacket, kBaseTimestamp + 1000));

    EXPECT_EQ(session.plaintextDnsResponses(), 1u);
    EXPECT_FALSE(session.flows(kBaseTimestamp + 2000).empty());
    EXPECT_TRUE(session.lookupHostname("93.184.216.34").has_value());

    session.clear();

    EXPECT_EQ(session.plaintextDnsResponses(), 0u);
    EXPECT_EQ(session.encryptedDnsPackets(), 0u);
    EXPECT_FALSE(session.echAdvertised());
    EXPECT_TRUE(session.flows(kBaseTimestamp + 2000).empty());
    EXPECT_FALSE(session.lookupHostname("93.184.216.34").has_value());
}
