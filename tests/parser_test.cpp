#include "PacketBuilders.hpp"

#include "capture/CaptureEngine.hpp"
#include "core/DNSParser.hpp"
#include "core/FlowAggregator.hpp"
#include "core/GeoIPResolver.hpp"
#include "core/HostnameCache.hpp"
#include "core/LinkType.hpp"
#include "core/PacketQueue.hpp"
#include "core/ProtocolParser.hpp"
#include "core/QuicParser.hpp"
#include "core/QuicTracker.hpp"
#include "core/TlsReassembler.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

    using namespace test;

    void writePcap(const std::filesystem::path& path, const std::vector<uint8_t>& packet,
        uint32_t linkType = 1 /* DLT_EN10MB */) {
        std::vector<uint8_t> bytes;
        // Little-endian PCAP global header.
        appendU32LE(bytes, 0xA1B2C3D4);
        bytes.insert(bytes.end(), {0x02, 0x00, 0x04, 0x00});
        appendU32LE(bytes, 0); // thiszone
        appendU32LE(bytes, 0); // sigfigs
        appendU32LE(bytes, 65535);
        appendU32LE(bytes, linkType);

        appendU32LE(bytes, 1'700'000'000);
        appendU32LE(bytes, 123'456);
        appendU32LE(bytes, static_cast<uint32_t>(packet.size()));
        appendU32LE(bytes, static_cast<uint32_t>(packet.size()));
        bytes.insert(bytes.end(), packet.begin(), packet.end());

        std::ofstream output(path, std::ios::binary);
        ASSERT_TRUE(output) << "Unable to create fixture: " << path.string();
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(output.good()) << "Unable to write fixture: " << path.string();
    }

    void writePcapMulti(const std::filesystem::path& path,
        const std::vector<std::vector<uint8_t>>& packets, uint32_t linkType = 1) {
        std::vector<uint8_t> bytes;
        appendU32LE(bytes, 0xA1B2C3D4);
        bytes.insert(bytes.end(), {0x02, 0x00, 0x04, 0x00});
        appendU32LE(bytes, 0);
        appendU32LE(bytes, 0);
        appendU32LE(bytes, 65535);
        appendU32LE(bytes, linkType);

        uint32_t microseconds = 0;
        for (const auto& packet : packets) {
            appendU32LE(bytes, 1'700'000'000);
            appendU32LE(bytes, microseconds);
            appendU32LE(bytes, static_cast<uint32_t>(packet.size()));
            appendU32LE(bytes, static_cast<uint32_t>(packet.size()));
            bytes.insert(bytes.end(), packet.begin(), packet.end());
            microseconds += 1000;
        }

        std::ofstream output(path, std::ios::binary);
        ASSERT_TRUE(output) << "Unable to create fixture: " << path.string();
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(output.good());
    }

    std::vector<core::ParsedPacket> loadFixture(const std::filesystem::path& path) {
        core::PacketQueue queue;
        capture::CaptureEngine capture(queue);
        if (!capture.openFile(path.string())) return {};

        std::vector<core::ParsedPacket> packets;
        while (auto raw = queue.try_pop()) {
            packets.push_back(core::ProtocolParser::parse(*raw));
        }
        return packets;
    }

    class OfflinePcapTest : public ::testing::Test {
    protected:
        void SetUp() override {
            fixtureDirectory = std::filesystem::temp_directory_path() / "netprobe-pcap-fixtures";
            std::filesystem::create_directories(fixtureDirectory);
        }

        void TearDown() override {
            std::error_code error;
            std::filesystem::remove_all(fixtureDirectory, error);
        }

        std::filesystem::path fixtureDirectory;
    };
}

namespace {
    // Write a minimal valid PCAPNG file containing one Ethernet packet.
    // Block layout (all little-endian): Section Header Block (SHB),
    // Interface Description Block (IDB, link type 1 = Ethernet),
    // Enhanced Packet Block (EPB) with the supplied payload.
    void writePcapng(const std::filesystem::path& path, const std::vector<uint8_t>& packet) {
        std::vector<uint8_t> bytes;

        // --- Section Header Block ---
        appendU32LE(bytes, 0x0A0D0D0A); // block type: SHB
        appendU32LE(bytes, 28);         // total block length
        appendU32LE(bytes, 0x1A2B3C4D); // byte-order magic (little-endian)
        bytes.insert(bytes.end(), {0x01, 0x00, 0x00, 0x00}); // version 1.0
        // section length = -1 (unknown), 8 bytes
        bytes.insert(bytes.end(), 8, 0xFF);
        appendU32LE(bytes, 28);         // block length (trailer)

        // --- Interface Description Block ---
        appendU32LE(bytes, 0x00000001); // block type: IDB
        appendU32LE(bytes, 20);         // total block length
        appendU32LE(bytes, 1);          // link type: LINKTYPE_ETHERNET
        appendU32LE(bytes, 65535);      // snap length
        appendU32LE(bytes, 20);         // block length (trailer)

        // --- Enhanced Packet Block ---
        const uint32_t capturedLen = static_cast<uint32_t>(packet.size());
        // EPB payload padding to 4-byte alignment.
        const uint32_t padding = (4 - (capturedLen % 4)) % 4;
        const uint32_t totalBlockLen = 32 + capturedLen + padding;
        appendU32LE(bytes, 0x00000006); // block type: EPB
        appendU32LE(bytes, totalBlockLen);
        appendU32LE(bytes, 0);          // interface id
        appendU32LE(bytes, 0);          // timestamp high
        appendU32LE(bytes, 0);          // timestamp low (irrelevant for parsing)
        appendU32LE(bytes, capturedLen); // captured length
        appendU32LE(bytes, capturedLen); // original length
        bytes.insert(bytes.end(), packet.begin(), packet.end());
        for (uint32_t i = 0; i < padding; ++i) bytes.push_back(0);
        appendU32LE(bytes, totalBlockLen); // block length (trailer)

        std::ofstream out(path, std::ios::binary);
        ASSERT_TRUE(out);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
}

// libpcap / Npcap natively read pcapng via pcap_open_offline. This test
// constructs a minimal pcapng on disk and confirms NetProbe's offline loader
// pulls the inner packet through end-to-end.
TEST_F(OfflinePcapTest, LoadsPcapngFixture) {
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, 28, 17, {10, 0, 0, 5}, {8, 8, 8, 8});
    appendU16(packet, 53000);
    appendU16(packet, 53);
    packet.insert(packet.end(), {0x00, 0x08, 0x00, 0x00});

    const auto fixture = fixtureDirectory / "minimal.pcapng";
    writePcapng(fixture, packet);
    const auto packets = loadFixture(fixture);

    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0].protocol, "UDP");
    EXPECT_EQ(packets[0].srcIP, "10.0.0.5");
    EXPECT_EQ(packets[0].dstIP, "8.8.8.8");
    EXPECT_EQ(packets[0].dstPort, 53);
}

TEST_F(OfflinePcapTest, LoadsHttpsClientHelloFixture) {
    const auto tls = makeTlsClientHello("example.com");
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + tls.size()), 6, {192, 168, 1, 10}, {93, 184, 216, 34});
    appendU16(packet, 50123);
    appendU16(packet, 443);
    packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00});
    packet.insert(packet.end(), tls.begin(), tls.end());

    const auto fixture = fixtureDirectory / "https_client_hello.pcap";
    writePcap(fixture, packet);
    const auto packets = loadFixture(fixture);

    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0].protocol, "TCP");
    EXPECT_EQ(packets[0].srcIP, "192.168.1.10");
    EXPECT_EQ(packets[0].dstIP, "93.184.216.34");
    EXPECT_EQ(packets[0].dstPort, 443);
    EXPECT_EQ(packets[0].sni, "example.com");
}

TEST_F(OfflinePcapTest, LoadsDnsQueryFixture) {
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, 28, 17, {10, 0, 0, 5}, {8, 8, 8, 8});
    appendU16(packet, 53000);
    appendU16(packet, 53);
    packet.insert(packet.end(), {0x00, 0x08, 0x00, 0x00});

    const auto fixture = fixtureDirectory / "dns_query.pcap";
    writePcap(fixture, packet);
    const auto packets = loadFixture(fixture);

    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0].protocol, "UDP");
    EXPECT_EQ(packets[0].srcIP, "10.0.0.5");
    EXPECT_EQ(packets[0].dstIP, "8.8.8.8");
    EXPECT_EQ(packets[0].srcPort, 53000);
    EXPECT_EQ(packets[0].dstPort, 53);
}

TEST_F(OfflinePcapTest, LoadsArpFixture) {
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0806);
    appendU16(packet, 1);      // Ethernet hardware type
    appendU16(packet, 0x0800); // IPv4 protocol type
    packet.insert(packet.end(), {6, 4});
    appendU16(packet, 1);      // ARP request
    packet.insert(packet.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 192, 168, 1, 10});
    packet.insert(packet.end(), 6, 0x00);
    packet.insert(packet.end(), {192, 168, 1, 1});

    const auto fixture = fixtureDirectory / "arp_request.pcap";
    writePcap(fixture, packet);
    const auto packets = loadFixture(fixture);

    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0].protocol, "ARP");
    EXPECT_EQ(packets[0].srcIP, "192.168.1.10");
    EXPECT_EQ(packets[0].dstIP, "192.168.1.1");
    EXPECT_EQ(packets[0].service, "ARP request");
}

TEST_F(OfflinePcapTest, ExportsRetainedSessionAsReadablePcap) {
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, 28, 17, {10, 0, 0, 5}, {8, 8, 8, 8});
    appendU16(packet, 53000);
    appendU16(packet, 53);
    packet.insert(packet.end(), {0x00, 0x08, 0x00, 0x00});

    const auto source = fixtureDirectory / "source.pcap";
    const auto exported = fixtureDirectory / "exported-session.pcap";
    writePcap(source, packet);

    core::PacketQueue sourceQueue;
    capture::CaptureEngine sourceCapture(sourceQueue);
    ASSERT_TRUE(sourceCapture.openFile(source.string()));
    std::string error;
    ASSERT_TRUE(sourceCapture.exportSession(exported.string(), error)) << error;

    core::PacketQueue exportedQueue;
    capture::CaptureEngine exportedCapture(exportedQueue);
    ASSERT_TRUE(exportedCapture.openFile(exported.string()));
    const auto exportedPacket = exportedQueue.try_pop();
    ASSERT_TRUE(exportedPacket.has_value());
    EXPECT_EQ(exportedPacket->length, packet.size());
    EXPECT_EQ(exportedPacket->payload, packet);
}

TEST(DNSParserTest, ParsesCnameAndAddressAnswersIntoHostnameCache) {
    std::vector<uint8_t> dns;
    appendU16(dns, 0x1234); // Transaction ID
    appendU16(dns, 0x8180); // Standard response, recursion available
    appendU16(dns, 1);      // One question
    appendU16(dns, 3);      // CNAME, A, and AAAA answers
    appendU16(dns, 0);
    appendU16(dns, 0);
    appendDnsName(dns, "www.example.com");
    appendU16(dns, 1);
    appendU16(dns, 1);

    // www.example.com CNAME edge.example.com; the owner uses DNS compression.
    dns.insert(dns.end(), {0xC0, 0x0C});
    appendU16(dns, 5);
    appendU16(dns, 1);
    appendU32BE(dns, 60);
    std::vector<uint8_t> canonicalName;
    appendDnsName(canonicalName, "edge.example.com");
    appendU16(dns, static_cast<uint16_t>(canonicalName.size()));
    dns.insert(dns.end(), canonicalName.begin(), canonicalName.end());

    appendDnsName(dns, "edge.example.com");
    appendU16(dns, 1);
    appendU16(dns, 1);
    appendU32BE(dns, 60);
    appendU16(dns, 4);
    dns.insert(dns.end(), {93, 184, 216, 34});

    appendDnsName(dns, "edge.example.com");
    appendU16(dns, 28);
    appendU16(dns, 1);
    appendU32BE(dns, 60);
    appendU16(dns, 16);
    dns.insert(dns.end(), {0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
        0x02, 0x48, 0x18, 0x93, 0x25, 0xC8, 0x19, 0x46});

    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 8 + dns.size()), 17, {8, 8, 8, 8}, {192, 168, 1, 10});
    appendU16(packet, 53);
    appendU16(packet, 53000);
    appendU16(packet, static_cast<uint16_t>(8 + dns.size()));
    appendU16(packet, 0);
    packet.insert(packet.end(), dns.begin(), dns.end());

    core::PacketData raw(1, static_cast<uint32_t>(packet.size()), static_cast<uint32_t>(packet.size()), packet.data());
    const auto response = core::DNSParser::parseResponse(raw);

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->queryName, "www.example.com");
    ASSERT_EQ(response->answers.size(), 3u);
    EXPECT_EQ(response->answers[0].type, core::DNSRecordType::CNAME);
    EXPECT_EQ(response->answers[0].value, "edge.example.com");
    EXPECT_EQ(response->answers[1].value, "93.184.216.34");
    EXPECT_EQ(response->answers[2].value, "2606:2800:220:1:248:1893:25c8:1946");

    core::HostnameCache cache;
    for (const auto& answer : response->answers) {
        if (answer.type == core::DNSRecordType::A || answer.type == core::DNSRecordType::AAAA) {
            cache.store(answer.value, response->queryName);
        }
    }
    const auto ipv4Hostname = cache.lookup("93.184.216.34");
    const auto ipv6Hostname = cache.lookup("2606:2800:220:1:248:1893:25c8:1946");
    ASSERT_TRUE(ipv4Hostname.has_value());
    ASSERT_TRUE(ipv6Hostname.has_value());
    EXPECT_EQ(*ipv4Hostname, "www.example.com");
    EXPECT_EQ(*ipv6Hostname, "www.example.com");
}

TEST(FlowAggregatorTest, CombinesBothDirectionsAndTracksRate) {
    constexpr int64_t start = 1'700'000'000'000'000;
    core::ParsedPacket outbound;
    outbound.timestamp = start;
    outbound.srcIP = "192.168.1.10";
    outbound.dstIP = "35.186.224.47";
    outbound.srcPort = 51000;
    outbound.dstPort = 443;
    outbound.protocol = "TCP";
    outbound.length = 120;
    outbound.sni = "spotify.com";
    outbound.service = "Spotify";

    core::ParsedPacket inbound;
    inbound.timestamp = start + 500'000;
    inbound.srcIP = outbound.dstIP;
    inbound.dstIP = outbound.srcIP;
    inbound.srcPort = 443;
    inbound.dstPort = outbound.srcPort;
    inbound.protocol = "TCP";
    inbound.length = 240;

    core::FlowAggregator flows;
    flows.update(outbound);
    flows.update(inbound);
    const auto snapshot = flows.snapshot(start + 750'000);

    ASSERT_EQ(snapshot.size(), 1u);
    const auto& flow = snapshot.front();
    EXPECT_EQ(flow.key.srcIP, "192.168.1.10");
    EXPECT_EQ(flow.key.dstIP, "35.186.224.47");
    EXPECT_EQ(flow.key.dstPort, 443);
    EXPECT_EQ(flow.packets, 2u);
    EXPECT_EQ(flow.bytesUp, 120u);
    EXPECT_EQ(flow.bytesDown, 240u);
    EXPECT_EQ(flow.hostname, "spotify.com");
    EXPECT_EQ(flow.service, "Spotify");
    EXPECT_DOUBLE_EQ(flow.rateBytesPerSecond, 360.0);
    EXPECT_TRUE(core::FlowAggregator::matches(inbound, flow.key));
}

TEST(GeoIPResolverTest, ReadsCountryAndAsnFromMaxMindDatabases) {
    const std::filesystem::path testDataDirectory = LIBMAXMINDDB_TEST_DATA_DIR;
    const auto countryDatabase = testDataDirectory / "GeoLite2-Country-Test.mmdb";
    const auto asnDatabase = testDataDirectory / "GeoLite2-ASN-Test.mmdb";

    core::GeoIPResolver resolver(countryDatabase, asnDatabase, 2);
    ASSERT_TRUE(resolver.isAvailable());

    const auto countryInfo = resolver.lookup("2.125.160.216");
    EXPECT_EQ(countryInfo.country, "GB");

    const auto asnInfo = resolver.lookup("1.0.0.1");
    EXPECT_EQ(asnInfo.asn, 15169u);
    EXPECT_EQ(asnInfo.organization, "Google Inc.");

    // Repeat the first lookup to exercise the LRU cache path.
    EXPECT_EQ(resolver.lookup("2.125.160.216").country, "GB");
}

namespace {
    core::ParsedPacket makeTcpFlowPacket(int64_t timestamp,
                                         std::string srcIP,
                                         std::string dstIP,
                                         uint16_t srcPort,
                                         uint16_t dstPort,
                                         uint32_t length) {
        core::ParsedPacket packet;
        packet.timestamp = timestamp;
        packet.srcIP = std::move(srcIP);
        packet.dstIP = std::move(dstIP);
        packet.srcPort = srcPort;
        packet.dstPort = dstPort;
        packet.protocol = "TCP";
        packet.length = length;
        return packet;
    }
}

TEST(FlowAggregatorTest, SeparatesIndependentFlows) {
    core::FlowAggregator flows;
    flows.update(makeTcpFlowPacket(1'000, "192.168.1.10", "1.1.1.1", 51000, 443, 100));
    flows.update(makeTcpFlowPacket(2'000, "192.168.1.10", "8.8.8.8", 51001, 443, 200));
    flows.update(makeTcpFlowPacket(3'000, "192.168.1.10", "1.1.1.1", 51000, 443, 50));

    const auto snapshot = flows.snapshot(4'000);
    ASSERT_EQ(snapshot.size(), 2u);
    uint64_t total = 0;
    for (const auto& flow : snapshot) total += flow.bytesUp + flow.bytesDown;
    EXPECT_EQ(total, 350u);
}

TEST(FlowAggregatorTest, IgnoresNonIpProtocols) {
    core::ParsedPacket arp;
    arp.protocol = "ARP";
    arp.srcIP = "192.168.1.10";
    arp.dstIP = "192.168.1.1";
    arp.length = 60;

    core::FlowAggregator flows;
    flows.update(arp);
    EXPECT_TRUE(flows.snapshot(0).empty());
    EXPECT_FALSE(core::FlowAggregator::keyFor(arp).has_value());
}

TEST(FlowAggregatorTest, RateExcludesSamplesOlderThanOneSecond) {
    core::FlowAggregator flows;
    constexpr int64_t base = 10'000'000;
    flows.update(makeTcpFlowPacket(base, "192.168.1.10", "1.1.1.1", 51000, 443, 1000));
    flows.update(makeTcpFlowPacket(base + 500'000, "192.168.1.10", "1.1.1.1", 51000, 443, 1000));
    flows.update(makeTcpFlowPacket(base + 2'000'000, "192.168.1.10", "1.1.1.1", 51000, 443, 500));

    // At base + 2.5s, only the third sample falls within the trailing 1s window.
    const auto snapshot = flows.snapshot(base + 2'500'000);
    ASSERT_EQ(snapshot.size(), 1u);
    EXPECT_EQ(snapshot.front().packets, 3u);
    EXPECT_DOUBLE_EQ(snapshot.front().rateBytesPerSecond, 500.0);
}

TEST(FlowAggregatorTest, SetHostnameForAddressAppliesToMatchingFlows) {
    core::FlowAggregator flows;
    flows.update(makeTcpFlowPacket(1'000, "192.168.1.10", "93.184.216.34", 51000, 443, 100));
    flows.update(makeTcpFlowPacket(2'000, "192.168.1.10", "8.8.8.8", 51001, 443, 100));
    flows.setHostnameForAddress("93.184.216.34", "example.com");

    const auto snapshot = flows.snapshot(3'000);
    ASSERT_EQ(snapshot.size(), 2u);
    for (const auto& flow : snapshot) {
        if (flow.key.dstIP == "93.184.216.34") EXPECT_EQ(flow.hostname, "example.com");
        else EXPECT_TRUE(flow.hostname.empty());
    }
}

TEST(FlowAggregatorTest, NormalizesServerToClientDirection) {
    // First packet flows server->client (src is well-known port 443).
    // The aggregator should still key the flow client-side and credit bytes to bytesDown.
    core::ParsedPacket downFirst = makeTcpFlowPacket(1'000, "93.184.216.34", "192.168.1.10", 443, 51000, 400);
    core::FlowAggregator flows;
    flows.update(downFirst);
    const auto snapshot = flows.snapshot(2'000);
    ASSERT_EQ(snapshot.size(), 1u);
    EXPECT_EQ(snapshot.front().key.srcIP, "192.168.1.10");
    EXPECT_EQ(snapshot.front().key.dstIP, "93.184.216.34");
    EXPECT_EQ(snapshot.front().bytesDown, 400u);
    EXPECT_EQ(snapshot.front().bytesUp, 0u);
}

TEST(FlowAggregatorTest, ComputesInitialRttFromSynAndSynAck) {
    // Client → server SYN at t=0, server → client SYN-ACK at t=42ms.
    // We expect the aggregator to credit the flow with a 42_000 µs initial RTT.
    constexpr int64_t synTime    = 1'000'000;
    constexpr int64_t synAckTime = synTime + 42'000;

    core::ParsedPacket syn = makeTcpFlowPacket(synTime, "192.168.1.10", "93.184.216.34", 50000, 443, 60);
    syn.tcpSyn = true;
    syn.tcpAck = false;

    core::ParsedPacket synAck = makeTcpFlowPacket(synAckTime, "93.184.216.34", "192.168.1.10", 443, 50000, 60);
    synAck.tcpSyn = true;
    synAck.tcpAck = true;

    core::FlowAggregator flows;
    flows.update(syn);
    flows.update(synAck);
    const auto snapshot = flows.snapshot(synAckTime + 100'000);
    ASSERT_EQ(snapshot.size(), 1u);
    EXPECT_EQ(snapshot.front().initialRttMicroseconds, 42'000);
}

TEST(FlowAggregatorTest, IgnoresSynRetransmitForRttCalculation) {
    // A retransmitted SYN should not push the RTT measurement out — once we
    // have the first SYN timestamp, that's the value we use.
    constexpr int64_t firstSyn  = 1'000'000;
    constexpr int64_t secondSyn = firstSyn + 1'000'000; // 1s later
    constexpr int64_t synAck    = firstSyn + 30'000;   // SYN-ACK arrives before retransmit

    core::ParsedPacket syn1 = makeTcpFlowPacket(firstSyn, "192.168.1.10", "8.8.8.8", 51000, 443, 60);
    syn1.tcpSyn = true;

    core::ParsedPacket syn2 = makeTcpFlowPacket(secondSyn, "192.168.1.10", "8.8.8.8", 51000, 443, 60);
    syn2.tcpSyn = true;

    core::ParsedPacket sa = makeTcpFlowPacket(synAck, "8.8.8.8", "192.168.1.10", 443, 51000, 60);
    sa.tcpSyn = true;
    sa.tcpAck = true;

    core::FlowAggregator flows;
    flows.update(syn1);
    flows.update(sa);
    flows.update(syn2); // retransmit after handshake completed
    const auto snapshot = flows.snapshot(secondSyn + 500'000);
    ASSERT_EQ(snapshot.size(), 1u);
    EXPECT_EQ(snapshot.front().initialRttMicroseconds, 30'000);
}

TEST(FlowAggregatorTest, NoRttWhenFlowStartedBeforeCapture) {
    // No SYN seen — flow starts with mid-stream data — RTT remains unset.
    core::ParsedPacket data = makeTcpFlowPacket(1'000'000, "192.168.1.10", "8.8.8.8", 51000, 443, 1400);
    data.tcpAck = true; // ACK only, no SYN

    core::FlowAggregator flows;
    flows.update(data);
    const auto snapshot = flows.snapshot(2'000'000);
    ASSERT_EQ(snapshot.size(), 1u);
    EXPECT_EQ(snapshot.front().initialRttMicroseconds, 0);
}

TEST(FlowAggregatorTest, ClearRemovesAllFlows) {
    core::FlowAggregator flows;
    flows.update(makeTcpFlowPacket(1'000, "192.168.1.10", "1.1.1.1", 51000, 443, 100));
    ASSERT_EQ(flows.snapshot(2'000).size(), 1u);
    flows.clear();
    EXPECT_TRUE(flows.snapshot(2'000).empty());
}

namespace {
    core::PacketData makeNumberedPacket(int64_t id, uint32_t length = 64) {
        const uint8_t marker = static_cast<uint8_t>(id & 0xFF);
        return core::PacketData(id, length, 1, &marker);
    }
}

TEST(PacketQueueTest, PreservesFifoOrderingUnderCapacity) {
    core::PacketQueue queue(8);
    for (int64_t i = 1; i <= 5; ++i) queue.push(makeNumberedPacket(i));
    EXPECT_EQ(queue.size(), 5u);
    EXPECT_EQ(queue.droppedPackets(), 0u);

    for (int64_t i = 1; i <= 5; ++i) {
        auto packet = queue.try_pop();
        ASSERT_TRUE(packet.has_value());
        EXPECT_EQ(packet->timestamp, i);
    }
    EXPECT_TRUE(queue.empty());
}

TEST(PacketQueueTest, DropsOldestWhenAtCapacity) {
    core::PacketQueue queue(3);
    for (int64_t i = 1; i <= 6; ++i) queue.push(makeNumberedPacket(i));

    EXPECT_EQ(queue.size(), 3u);
    EXPECT_EQ(queue.droppedPackets(), 3u);
    // FIFO eviction means packets 1, 2, 3 are gone; 4, 5, 6 remain.
    for (int64_t expected = 4; expected <= 6; ++expected) {
        auto packet = queue.try_pop();
        ASSERT_TRUE(packet.has_value());
        EXPECT_EQ(packet->timestamp, expected);
    }
}

TEST(PacketQueueTest, ZeroMaxSizeIsTreatedAsOne) {
    core::PacketQueue queue(0);
    queue.push(makeNumberedPacket(1));
    queue.push(makeNumberedPacket(2));
    EXPECT_EQ(queue.size(), 1u);
    EXPECT_EQ(queue.droppedPackets(), 1u);
    auto packet = queue.try_pop();
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->timestamp, 2);
}

TEST(PacketQueueTest, TryPopReturnsNulloptWhenEmpty) {
    core::PacketQueue queue;
    EXPECT_FALSE(queue.try_pop().has_value());
}

TEST(PacketQueueTest, BlockingPopWakesOnPush) {
    core::PacketQueue queue;
    std::atomic<bool> popped{false};
    std::thread consumer([&] {
        auto packet = queue.pop();
        EXPECT_EQ(packet.timestamp, 42);
        popped.store(true);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(popped.load());
    queue.push(makeNumberedPacket(42));
    consumer.join();
    EXPECT_TRUE(popped.load());
}

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

namespace {

    // ---- QUIC encryption helpers (mirror of QuicParser internals) ----
    //
    // The parser's correctness is proved end-to-end by constructing a real
    // QUIC v1 Initial packet (real key derivation, real AES-GCM, real header
    // protection) and confirming the parser recovers the SNI. We use mbedTLS
    // directly here for the encryption side.

    constexpr uint8_t kInitialSaltV1Test[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    };

    void hkdfExpandLabelTest(const uint8_t* secret, size_t secretLen,
                             const char* label, size_t labelLen,
                             uint8_t* out, size_t outLen) {
        static constexpr char kPrefix[] = "tls13 ";
        constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
        const size_t fullLabelLen = kPrefixLen + labelLen;
        uint8_t info[2 + 1 + 255 + 1] = {};
        size_t p = 0;
        info[p++] = static_cast<uint8_t>(outLen >> 8);
        info[p++] = static_cast<uint8_t>(outLen);
        info[p++] = static_cast<uint8_t>(fullLabelLen);
        std::memcpy(info + p, kPrefix, kPrefixLen); p += kPrefixLen;
        std::memcpy(info + p, label, labelLen);     p += labelLen;
        info[p++] = 0;
        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        ASSERT_EQ(mbedtls_hkdf_expand(md, secret, secretLen, info, p, out, outLen), 0);
    }

    struct QuicInitialKeys {
        uint8_t key[16];
        uint8_t iv[12];
        uint8_t hp[16];
    };

    void deriveClientKeys(const uint8_t* dcid, size_t dcidLen, QuicInitialKeys& out) {
        uint8_t initialSecret[32];
        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        ASSERT_EQ(mbedtls_hkdf_extract(md, kInitialSaltV1Test, sizeof(kInitialSaltV1Test),
                                        dcid, dcidLen, initialSecret), 0);
        uint8_t clientSecret[32];
        hkdfExpandLabelTest(initialSecret, 32, "client in", 9, clientSecret, 32);
        hkdfExpandLabelTest(clientSecret, 32, "quic key", 8, out.key, 16);
        hkdfExpandLabelTest(clientSecret, 32, "quic iv", 7, out.iv, 12);
        hkdfExpandLabelTest(clientSecret, 32, "quic hp", 7, out.hp, 16);
    }

    void appendVarint(std::vector<uint8_t>& out, uint64_t v) {
        if (v < 0x40) {
            out.push_back(static_cast<uint8_t>(v));
        } else if (v < 0x4000) {
            out.push_back(static_cast<uint8_t>(0x40 | (v >> 8)));
            out.push_back(static_cast<uint8_t>(v));
        } else {
            ASSERT_LE(v, 0x3FFFFFFFu);
            out.push_back(static_cast<uint8_t>(0x80 | (v >> 24)));
            out.push_back(static_cast<uint8_t>(v >> 16));
            out.push_back(static_cast<uint8_t>(v >> 8));
            out.push_back(static_cast<uint8_t>(v));
        }
    }

    // Build a minimal TLS 1.3 ClientHello with one SNI extension.
    std::vector<uint8_t> buildClientHello(const std::string& sni) {
        std::vector<uint8_t> body;
        body.push_back(0x03); body.push_back(0x03); // legacy_version TLS 1.2
        for (int i = 0; i < 32; ++i) body.push_back(static_cast<uint8_t>(0xA0 + i)); // random
        body.push_back(0x00); // empty session_id
        // cipher_suites: TLS_AES_128_GCM_SHA256
        body.push_back(0x00); body.push_back(0x02);
        body.push_back(0x13); body.push_back(0x01);
        // compression_methods: null
        body.push_back(0x01); body.push_back(0x00);

        // Extensions
        std::vector<uint8_t> exts;
        // server_name extension (type 0x0000)
        std::vector<uint8_t> sniExt;
        // server_name_list (one entry)
        const uint16_t nameLen = static_cast<uint16_t>(sni.size());
        const uint16_t listLen = static_cast<uint16_t>(3 + nameLen);
        sniExt.push_back(static_cast<uint8_t>(listLen >> 8));
        sniExt.push_back(static_cast<uint8_t>(listLen));
        sniExt.push_back(0x00); // name_type: host_name
        sniExt.push_back(static_cast<uint8_t>(nameLen >> 8));
        sniExt.push_back(static_cast<uint8_t>(nameLen));
        sniExt.insert(sniExt.end(), sni.begin(), sni.end());

        exts.push_back(0x00); exts.push_back(0x00); // extension_type
        exts.push_back(static_cast<uint8_t>(sniExt.size() >> 8));
        exts.push_back(static_cast<uint8_t>(sniExt.size()));
        exts.insert(exts.end(), sniExt.begin(), sniExt.end());

        body.push_back(static_cast<uint8_t>(exts.size() >> 8));
        body.push_back(static_cast<uint8_t>(exts.size()));
        body.insert(body.end(), exts.begin(), exts.end());

        std::vector<uint8_t> handshake;
        handshake.push_back(0x01); // ClientHello
        handshake.push_back(static_cast<uint8_t>(body.size() >> 16));
        handshake.push_back(static_cast<uint8_t>(body.size() >> 8));
        handshake.push_back(static_cast<uint8_t>(body.size()));
        handshake.insert(handshake.end(), body.begin(), body.end());
        return handshake;
    }

    // Wrap handshake bytes in a CRYPTO frame; pad out to padTo bytes.
    std::vector<uint8_t> buildInitialPlaintext(const std::vector<uint8_t>& clientHello,
                                                size_t padTo) {
        std::vector<uint8_t> plain;
        plain.push_back(0x06); // CRYPTO frame
        appendVarint(plain, 0); // offset
        appendVarint(plain, clientHello.size()); // length
        plain.insert(plain.end(), clientHello.begin(), clientHello.end());
        while (plain.size() < padTo) plain.push_back(0x00); // PADDING frames
        return plain;
    }

    // Encrypt plaintext + apply header protection → final on-wire bytes.
    std::vector<uint8_t> buildQuicInitialPacket(const std::vector<uint8_t>& dcid,
                                                 const std::vector<uint8_t>& plaintext,
                                                 uint32_t packetNumber = 0) {
        QuicInitialKeys keys{};
        deriveClientKeys(dcid.data(), dcid.size(), keys);

        // Header: first byte (Long Header + Fixed + Initial + PN-length-1=4 -> 0xC3)
        std::vector<uint8_t> header;
        header.push_back(0xC3); // 11000011: long + fixed + initial + pnLen=4
        // Version
        header.push_back(0x00); header.push_back(0x00); header.push_back(0x00); header.push_back(0x01);
        // DCID
        header.push_back(static_cast<uint8_t>(dcid.size()));
        header.insert(header.end(), dcid.begin(), dcid.end());
        // SCID (empty)
        header.push_back(0x00);
        // Token (empty)
        appendVarint(header, 0);
        // Length placeholder — reserve exactly 2 bytes (max value for the
        // 2-byte varint form is 0x3FFF; we patch the real length below).
        const size_t lengthFieldOffset = header.size();
        header.push_back(0x40);
        header.push_back(0x00);
        const size_t pnOffset = header.size();
        // Packet number (4 bytes big-endian)
        header.push_back(static_cast<uint8_t>(packetNumber >> 24));
        header.push_back(static_cast<uint8_t>(packetNumber >> 16));
        header.push_back(static_cast<uint8_t>(packetNumber >> 8));
        header.push_back(static_cast<uint8_t>(packetNumber));

        // Compute Length value: pn (4) + ciphertext (= plaintext size) + tag (16)
        const uint64_t lenValue = 4 + plaintext.size() + 16;
        EXPECT_LT(lenValue, 0x4000u);
        header[lengthFieldOffset]     = static_cast<uint8_t>(0x40 | (lenValue >> 8));
        header[lengthFieldOffset + 1] = static_cast<uint8_t>(lenValue);

        // Build nonce: iv XOR packetNumber (right-aligned in 12 bytes)
        uint8_t nonce[12];
        std::memcpy(nonce, keys.iv, 12);
        for (int i = 0; i < 4; ++i) {
            nonce[12 - 1 - i] ^= static_cast<uint8_t>((packetNumber >> (i * 8)) & 0xFF);
        }

        // Encrypt with AES-128-GCM
        std::vector<uint8_t> ciphertext(plaintext.size());
        uint8_t tag[16];
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        EXPECT_EQ(mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, keys.key, 128), 0);
        EXPECT_EQ(mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
            plaintext.size(),
            nonce, sizeof(nonce),
            header.data(), header.size(),
            plaintext.data(), ciphertext.data(),
            16, tag), 0);
        mbedtls_gcm_free(&gcm);

        // Apply header protection
        // Sample = 16 bytes at pnOffset + 4
        std::vector<uint8_t> packet = header;
        packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
        packet.insert(packet.end(), tag, tag + 16);

        const uint8_t* sample = packet.data() + pnOffset + 4;
        uint8_t mask[16] = {};
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        EXPECT_EQ(mbedtls_aes_setkey_enc(&aes, keys.hp, 128), 0);
        EXPECT_EQ(mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, sample, mask), 0);
        mbedtls_aes_free(&aes);

        // Mask first byte's low nibble + 4-byte PN
        packet[0] ^= (mask[0] & 0x0F);
        for (int i = 0; i < 4; ++i) packet[pnOffset + i] ^= mask[i + 1];

        return packet;
    }

}

// End-to-end test: build a QUIC v1 Client Initial with a known SNI using
// our own encryption helpers, then confirm QuicParser recovers the SNI by
// running the full pipeline (key derivation → header unprotection → AES-GCM
// decrypt → CRYPTO frame reassembly → TLS ClientHello extension walk).
TEST(QuicParserTest, ExtractsSniFromSyntheticClientInitial) {
    const std::vector<uint8_t> dcid = {
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
    };
    const auto ch = buildClientHello("netprobe.example.com");
    const auto plaintext = buildInitialPlaintext(ch, 1162); // RFC 9001 §A.2 size
    const auto packet = buildQuicInitialPacket(dcid, plaintext);

    const auto sni = core::QuicParser::extractInitialSni(packet.data(), packet.size());
    ASSERT_TRUE(sni.has_value());
    EXPECT_EQ(*sni, "netprobe.example.com");
}

TEST(QuicParserTest, ExtractsDifferentSniFromDifferentDcid) {
    const std::vector<uint8_t> dcid = {0xde, 0xad, 0xbe, 0xef};
    const auto ch = buildClientHello("api.acme.test");
    const auto plaintext = buildInitialPlaintext(ch, 1162);
    const auto packet = buildQuicInitialPacket(dcid, plaintext, 42);

    const auto sni = core::QuicParser::extractInitialSni(packet.data(), packet.size());
    ASSERT_TRUE(sni.has_value());
    EXPECT_EQ(*sni, "api.acme.test");
}

TEST(QuicParserTest, RejectsNonQuicTraffic) {
    const std::vector<uint8_t> garbage(64, 0x55);
    EXPECT_FALSE(core::QuicParser::extractInitialSni(garbage.data(), garbage.size()).has_value());
}

TEST(QuicParserTest, RejectsTooShortInput) {
    const std::vector<uint8_t> tiny = {0xc0, 0x00};
    EXPECT_FALSE(core::QuicParser::extractInitialSni(tiny.data(), tiny.size()).has_value());
    EXPECT_FALSE(core::QuicParser::extractInitialSni(nullptr, 0).has_value());
}

// ---------------------------------------------------------------------------
// Link-layer encapsulation
// ---------------------------------------------------------------------------

namespace {
    // IPv4 + UDP with no link header, so each link-type test can prepend its own.
    std::vector<uint8_t> ipv4UdpBody() {
        std::vector<uint8_t> bytes;
        appendIPv4Header(bytes, 28, 17, {10, 0, 0, 5}, {8, 8, 8, 8});
        appendUdpHeader(bytes, 53000, 53, 0);
        return bytes;
    }

    core::ParsedPacket parseWithLink(const std::vector<uint8_t>& packet, core::LinkType link) {
        const core::PacketData raw(1, static_cast<uint32_t>(packet.size()),
            static_cast<uint32_t>(packet.size()), packet.data(), link);
        return core::ProtocolParser::parse(raw);
    }
}

TEST(LinkTypeTest, DecodesLinuxCookedCapture) {
    std::vector<uint8_t> packet(14, 0x00); // packet type, ARPHRD, addr len, address
    appendU16(packet, 0x0800);             // EtherType at offset 14
    const auto body = ipv4UdpBody();
    packet.insert(packet.end(), body.begin(), body.end());

    const auto parsed = parseWithLink(packet, core::LinkType::LinuxSLL);
    EXPECT_EQ(parsed.protocol, "UDP");
    EXPECT_EQ(parsed.srcIP, "10.0.0.5");
    EXPECT_EQ(parsed.dstPort, 53);
}

TEST(LinkTypeTest, DecodesLinuxCookedV2Capture) {
    std::vector<uint8_t> packet;
    appendU16(packet, 0x0800);      // EtherType comes first in SLL2
    packet.insert(packet.end(), 18, 0x00);
    const auto body = ipv4UdpBody();
    packet.insert(packet.end(), body.begin(), body.end());

    const auto parsed = parseWithLink(packet, core::LinkType::LinuxSLL2);
    EXPECT_EQ(parsed.protocol, "UDP");
    EXPECT_EQ(parsed.srcIP, "10.0.0.5");
}

TEST(LinkTypeTest, DecodesBsdLoopbackCapture) {
    std::vector<uint8_t> packet = {0x02, 0x00, 0x00, 0x00}; // AF_INET, host byte order
    const auto body = ipv4UdpBody();
    packet.insert(packet.end(), body.begin(), body.end());

    const auto parsed = parseWithLink(packet, core::LinkType::NullLoopback);
    EXPECT_EQ(parsed.protocol, "UDP");
    EXPECT_EQ(parsed.dstIP, "8.8.8.8");
}

TEST(LinkTypeTest, DecodesRawIpCapture) {
    const auto parsed = parseWithLink(ipv4UdpBody(), core::LinkType::RawIP);
    EXPECT_EQ(parsed.protocol, "UDP");
    EXPECT_EQ(parsed.srcIP, "10.0.0.5");
}

// Reading an Ethernet header off a cooked capture used to yield plausible-looking
// but wrong addresses. Naming the link type is what prevents that.
TEST(LinkTypeTest, EthernetDecodeOfCookedCaptureDoesNotMatchCookedDecode) {
    std::vector<uint8_t> packet(14, 0x00);
    appendU16(packet, 0x0800);
    const auto body = ipv4UdpBody();
    packet.insert(packet.end(), body.begin(), body.end());

    const auto cooked = parseWithLink(packet, core::LinkType::LinuxSLL);
    const auto asEthernet = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(cooked.srcIP, "10.0.0.5");
    EXPECT_NE(asEthernet.srcIP, "10.0.0.5");
}

TEST(LinkTypeTest, UnsupportedLinkTypeIsReportedNotGuessed) {
    const auto parsed = parseWithLink(ipv4UdpBody(), core::LinkType::Unsupported);
    EXPECT_EQ(parsed.protocol, "Unsupported link type");
    EXPECT_TRUE(parsed.srcIP.empty());
}

TEST_F(OfflinePcapTest, ExportPreservesNonEthernetLinkType) {
    // DLT_NULL == 0. Writing this back out as Ethernet would corrupt it.
    std::vector<uint8_t> packet = {0x02, 0x00, 0x00, 0x00};
    const auto body = ipv4UdpBody();
    packet.insert(packet.end(), body.begin(), body.end());

    const auto source = fixtureDirectory / "loopback.pcap";
    const auto exported = fixtureDirectory / "loopback-exported.pcap";
    writePcap(source, packet, 0);

    core::PacketQueue sourceQueue;
    capture::CaptureEngine sourceCapture(sourceQueue);
    ASSERT_TRUE(sourceCapture.openFile(source.string()));
    EXPECT_EQ(sourceCapture.linkType(), core::LinkType::NullLoopback);
    const auto sourcePacket = sourceQueue.try_pop();
    ASSERT_TRUE(sourcePacket.has_value());
    EXPECT_EQ(sourcePacket->linkType, core::LinkType::NullLoopback);

    std::string error;
    ASSERT_TRUE(sourceCapture.exportSession(exported.string(), error)) << error;

    core::PacketQueue exportedQueue;
    capture::CaptureEngine exportedCapture(exportedQueue);
    ASSERT_TRUE(exportedCapture.openFile(exported.string()));
    EXPECT_EQ(exportedCapture.linkType(), core::LinkType::NullLoopback);
    const auto reread = exportedQueue.try_pop();
    ASSERT_TRUE(reread.has_value());
    EXPECT_EQ(core::ProtocolParser::parse(*reread).srcIP, "10.0.0.5");
}

// ---------------------------------------------------------------------------
// Tunnels
// ---------------------------------------------------------------------------

TEST(TunnelTest, DescendsIntoGreEncapsulatedIPv4) {
    std::vector<uint8_t> inner;
    appendIPv4Header(inner, 28, 17, {192, 168, 1, 5}, {8, 8, 4, 4});
    appendUdpHeader(inner, 40000, 53, 0);

    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 4 + inner.size()), 47, {10, 0, 0, 1}, {10, 0, 0, 2});
    appendU16(packet, 0x0000); // GRE flags: version 0, no checksum/key/sequence
    appendU16(packet, 0x0800); // encapsulated protocol: IPv4
    packet.insert(packet.end(), inner.begin(), inner.end());

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.tunnel, "GRE");
    EXPECT_EQ(parsed.outerSrcIP, "10.0.0.1");
    EXPECT_EQ(parsed.outerDstIP, "10.0.0.2");
    EXPECT_EQ(parsed.srcIP, "192.168.1.5");
    EXPECT_EQ(parsed.dstIP, "8.8.4.4");
    EXPECT_EQ(parsed.protocol, "UDP");
    EXPECT_EQ(parsed.service, "DNS");
}

TEST(TunnelTest, DescendsIntoVxlanEncapsulatedFrame) {
    std::vector<uint8_t> innerFrame;
    appendEthernetHeader(innerFrame, 0x0800);
    appendIPv4Header(innerFrame, 28, 17, {172, 16, 0, 9}, {172, 16, 0, 1});
    appendUdpHeader(innerFrame, 41000, 123, 0);

    std::vector<uint8_t> vxlan = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00};
    vxlan.insert(vxlan.end(), innerFrame.begin(), innerFrame.end());

    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 8 + vxlan.size()), 17, {10, 1, 1, 1}, {10, 1, 1, 2});
    appendUdpHeader(packet, 50000, 4789, static_cast<uint16_t>(vxlan.size()));
    packet.insert(packet.end(), vxlan.begin(), vxlan.end());

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.tunnel, "VXLAN");
    EXPECT_EQ(parsed.outerSrcIP, "10.1.1.1");
    EXPECT_EQ(parsed.srcIP, "172.16.0.9");
    EXPECT_EQ(parsed.dstIP, "172.16.0.1");
    EXPECT_EQ(parsed.protocol, "UDP");
    EXPECT_EQ(parsed.service, "NTP");
}

TEST(TunnelTest, DescendsIntoIpInIp) {
    std::vector<uint8_t> inner;
    appendIPv4Header(inner, 28, 17, {192, 0, 2, 7}, {198, 51, 100, 3});
    appendUdpHeader(inner, 42000, 161, 0);

    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + inner.size()), 4, {10, 0, 0, 1}, {10, 0, 0, 2});
    packet.insert(packet.end(), inner.begin(), inner.end());

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.tunnel, "IP-in-IP");
    EXPECT_EQ(parsed.srcIP, "192.0.2.7");
    EXPECT_EQ(parsed.service, "SNMP");
}

// ESP carries other traffic but its payload is encrypted; we must say so rather
// than silently reporting the tunnel endpoints as the real conversation.
TEST(TunnelTest, MarksEspAsAnEncryptedTunnel) {
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, 40, 50, {10, 0, 0, 1}, {203, 0, 113, 9});
    packet.insert(packet.end(), 20, 0xAB);

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.protocol, "ESP");
    EXPECT_TRUE(parsed.encryptedTunnel);
    EXPECT_TRUE(parsed.tunnel.empty());
}

TEST(TunnelTest, MarksWireGuardAsAnEncryptedTunnel) {
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, 32, 17, {10, 0, 0, 1}, {203, 0, 113, 9});
    appendUdpHeader(packet, 51820, 51820, 4);
    packet.insert(packet.end(), 4, 0x01);

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.service, "WireGuard");
    EXPECT_TRUE(parsed.encryptedTunnel);
}

TEST(ProtocolParserTest, NamesNonIpEtherTypes) {
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x88CC); // LLDP
    packet.insert(packet.end(), 20, 0x00);

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.protocol, "LLDP");
}

// ---------------------------------------------------------------------------
// TLS on arbitrary ports, and across TCP segments
// ---------------------------------------------------------------------------

TEST(TlsTest, ExtractsSniOnNonStandardPort) {
    const auto tls = makeTlsClientHello("intranet.example.org");
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + tls.size()), 6, {192, 168, 1, 10}, {93, 184, 216, 34});
    appendTcpHeader(packet, 50123, 8443, 1, 0x18);
    packet.insert(packet.end(), tls.begin(), tls.end());

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.sni, "intranet.example.org");
    EXPECT_EQ(parsed.dstPort, 8443);
}

TEST(TlsTest, SingleSegmentClientHelloNeedsNoReassembly) {
    const auto tls = makeTlsClientHello("example.com");
    core::ParsedPacket packet;
    packet.protocol = "TCP";
    packet.srcIP = "192.168.1.10";
    packet.dstIP = "93.184.216.34";
    packet.srcPort = 50000;
    packet.dstPort = 443;
    packet.tcpSeq = 1000;

    core::TlsReassembler reassembler;
    // The parser already handled it, so the reassembler must not start tracking.
    EXPECT_FALSE(reassembler.feed(packet, tls.data(), tls.size()).has_value());
    EXPECT_EQ(reassembler.trackedStreamCount(), 0u);
}

// Post-quantum key shares push the ClientHello past a single MSS, so the SNI is
// only recoverable once the segments are stitched back together.
TEST(TlsTest, ReassemblesClientHelloSplitAcrossTcpSegments) {
    const auto tls = makeTlsClientHello("split.example.com");
    ASSERT_GT(tls.size(), 20u);
    const size_t firstHalf = tls.size() / 2;

    core::ParsedPacket first;
    first.protocol = "TCP";
    first.srcIP = "192.168.1.10";
    first.dstIP = "93.184.216.34";
    first.srcPort = 50000;
    first.dstPort = 443;
    first.tcpSeq = 1000;
    first.timestamp = 1'700'000'000'000'000;

    core::ParsedPacket second = first;
    second.tcpSeq = 1000 + static_cast<uint32_t>(firstHalf);
    second.timestamp = first.timestamp + 1000;

    core::TlsReassembler reassembler;
    EXPECT_FALSE(reassembler.feed(first, tls.data(), firstHalf).has_value());
    EXPECT_EQ(reassembler.trackedStreamCount(), 1u);

    const auto sni = reassembler.feed(second, tls.data() + firstHalf, tls.size() - firstHalf);
    ASSERT_TRUE(sni.has_value());
    EXPECT_EQ(*sni, "split.example.com");
    EXPECT_EQ(reassembler.trackedStreamCount(), 0u);
}

TEST(TlsTest, ReassemblerDropsStreamOnSequenceGap) {
    const auto tls = makeTlsClientHello("gap.example.com");
    const size_t firstHalf = tls.size() / 2;

    core::ParsedPacket first;
    first.protocol = "TCP";
    first.srcIP = "192.168.1.10";
    first.dstIP = "93.184.216.34";
    first.srcPort = 50000;
    first.dstPort = 443;
    first.tcpSeq = 1000;

    core::ParsedPacket outOfOrder = first;
    outOfOrder.tcpSeq = 9999; // neither the next segment nor a retransmit

    core::TlsReassembler reassembler;
    EXPECT_FALSE(reassembler.feed(first, tls.data(), firstHalf).has_value());
    EXPECT_FALSE(reassembler.feed(outOfOrder, tls.data() + firstHalf, tls.size() - firstHalf).has_value());
    EXPECT_EQ(reassembler.trackedStreamCount(), 0u);
}

// ---------------------------------------------------------------------------
// Cleartext HTTP
// ---------------------------------------------------------------------------

TEST(HttpTest, ExtractsHostHeaderAndRequestLine) {
    const auto request = makeHttpRequest("www.example.com", "/index.html");
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + request.size()), 6, {192, 168, 1, 10}, {93, 184, 216, 34});
    appendTcpHeader(packet, 50124, 80, 1, 0x18);
    packet.insert(packet.end(), request.begin(), request.end());

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.hostname, "www.example.com");
    EXPECT_EQ(parsed.info, "GET /index.html HTTP/1.1");
    EXPECT_EQ(parsed.service, "HTTP");
}

TEST(HttpTest, MapsHostHeaderToServiceCatalog) {
    const auto request = makeHttpRequest("www.youtube.com");
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + request.size()), 6, {192, 168, 1, 10}, {142, 250, 0, 1});
    appendTcpHeader(packet, 50125, 8080, 1, 0x18);
    packet.insert(packet.end(), request.begin(), request.end());

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.hostname, "www.youtube.com");
    EXPECT_EQ(parsed.service, "YouTube");
}

TEST(HttpTest, ParsesResponseStatusLine) {
    const std::string response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x0800);
    appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + response.size()), 6, {93, 184, 216, 34}, {192, 168, 1, 10});
    appendTcpHeader(packet, 80, 50124, 1, 0x18);
    packet.insert(packet.end(), response.begin(), response.end());

    const auto parsed = parseWithLink(packet, core::LinkType::Ethernet);
    EXPECT_EQ(parsed.info, "HTTP/1.1 404 Not Found");
}

// ---------------------------------------------------------------------------
// QUIC version handling and multi-packet ClientHello
// ---------------------------------------------------------------------------

namespace {
    // A CRYPTO frame carrying `data` at `offset` in the handshake stream.
    std::vector<uint8_t> buildCryptoFrame(uint64_t offset, const uint8_t* data, size_t length) {
        std::vector<uint8_t> frame;
        frame.push_back(0x06); // CRYPTO
        appendVarint(frame, offset);
        appendVarint(frame, length);
        frame.insert(frame.end(), data, data + length);
        return frame;
    }
}

TEST(QuicParserTest, LongHeaderDetectionAcceptsV1AndV2AndRejectsUnknown) {
    std::vector<uint8_t> v1 = {0xC3, 0x00, 0x00, 0x00, 0x01, 0x00};
    std::vector<uint8_t> v2 = {0xC3, 0x6B, 0x33, 0x43, 0xCF, 0x00};
    std::vector<uint8_t> unknown = {0xC3, 0xDE, 0xAD, 0xBE, 0xEF, 0x00};
    std::vector<uint8_t> shortHeader = {0x43, 0x00, 0x00, 0x00, 0x01, 0x00};

    EXPECT_TRUE(core::QuicParser::looksLikeLongHeader(v1.data(), v1.size()));
    EXPECT_TRUE(core::QuicParser::looksLikeLongHeader(v2.data(), v2.size()));
    EXPECT_FALSE(core::QuicParser::looksLikeLongHeader(unknown.data(), unknown.size()));
    EXPECT_FALSE(core::QuicParser::looksLikeLongHeader(shortHeader.data(), shortHeader.size()));
}

TEST(QuicParserTest, ParseInitialExposesConnectionIdAndCryptoFragment) {
    const std::vector<uint8_t> dcid = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};
    const auto clientHello = buildClientHello("fragments.example.com");
    const auto plaintext = buildInitialPlaintext(clientHello, 0);
    const auto packet = buildQuicInitialPacket(dcid, plaintext);

    const auto initial = core::QuicParser::parseInitial(packet.data(), packet.size());
    ASSERT_TRUE(initial.has_value());
    EXPECT_EQ(initial->destinationConnectionId, dcid);
    ASSERT_EQ(initial->crypto.size(), 1u);
    EXPECT_EQ(initial->crypto[0].offset, 0u);
    EXPECT_EQ(initial->crypto[0].data, clientHello);
}

// A ClientHello with a post-quantum key share exceeds QUIC's 1200-byte minimum
// datagram, so it arrives as several Initials sharing one connection id.
TEST(QuicTrackerTest, ReassemblesClientHelloAcrossTwoInitialPackets) {
    const std::vector<uint8_t> dcid = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    const auto clientHello = buildClientHello("pq.example.com");
    ASSERT_GT(clientHello.size(), 16u);
    const size_t split = clientHello.size() / 2;

    const auto firstPacket = buildQuicInitialPacket(dcid,
        buildCryptoFrame(0, clientHello.data(), split), 0);
    const auto secondPacket = buildQuicInitialPacket(dcid,
        buildCryptoFrame(split, clientHello.data() + split, clientHello.size() - split), 1);

    // Neither packet alone carries a complete ClientHello.
    EXPECT_FALSE(core::QuicParser::extractInitialSni(firstPacket.data(), firstPacket.size()).has_value());

    core::QuicTracker tracker;
    EXPECT_FALSE(tracker.feed(firstPacket.data(), firstPacket.size(), 1).has_value());
    EXPECT_EQ(tracker.trackedConnectionCount(), 1u);

    const auto sni = tracker.feed(secondPacket.data(), secondPacket.size(), 2);
    ASSERT_TRUE(sni.has_value());
    EXPECT_EQ(*sni, "pq.example.com");
    EXPECT_EQ(tracker.trackedConnectionCount(), 0u);
}

TEST(QuicTrackerTest, DoesNotMixConnectionsWithDifferentConnectionIds) {
    const std::vector<uint8_t> firstDcid = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    const std::vector<uint8_t> secondDcid = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    const auto clientHello = buildClientHello("mixed.example.com");
    const size_t split = clientHello.size() / 2;

    const auto firstHalf = buildQuicInitialPacket(firstDcid,
        buildCryptoFrame(0, clientHello.data(), split), 0);
    const auto secondHalfWrongConnection = buildQuicInitialPacket(secondDcid,
        buildCryptoFrame(split, clientHello.data() + split, clientHello.size() - split), 1);

    core::QuicTracker tracker;
    EXPECT_FALSE(tracker.feed(firstHalf.data(), firstHalf.size(), 1).has_value());
    EXPECT_FALSE(tracker.feed(secondHalfWrongConnection.data(), secondHalfWrongConnection.size(), 2).has_value());
    EXPECT_EQ(tracker.trackedConnectionCount(), 2u);
}

// ---------------------------------------------------------------------------
// DNS record coverage
// ---------------------------------------------------------------------------

namespace {
    // Wrap a DNS message in Ethernet/IPv4/UDP with source port 53.
    core::PacketData wrapDnsResponse(std::vector<uint8_t>& storage, const std::vector<uint8_t>& dns) {
        storage.clear();
        appendEthernetHeader(storage, 0x0800);
        appendIPv4Header(storage, static_cast<uint16_t>(20 + 8 + dns.size()), 17, {8, 8, 8, 8}, {10, 0, 0, 5});
        appendUdpHeader(storage, 53, 53000, static_cast<uint16_t>(dns.size()));
        storage.insert(storage.end(), dns.begin(), dns.end());
        return core::PacketData(1, static_cast<uint32_t>(storage.size()),
            static_cast<uint32_t>(storage.size()), storage.data());
    }
}

TEST(DNSParserTest, ConvertsReverseLookupNamesToAddresses) {
    const auto ipv4 = core::DNSParser::reverseNameToAddress("1.1.168.192.in-addr.arpa");
    ASSERT_TRUE(ipv4.has_value());
    EXPECT_EQ(*ipv4, "192.168.1.1");

    EXPECT_FALSE(core::DNSParser::reverseNameToAddress("www.example.com").has_value());
    EXPECT_FALSE(core::DNSParser::reverseNameToAddress("999.1.1.1.in-addr.arpa").has_value());
}

// PTR answers name the printers, NAS boxes, and routers that never appear in a
// forward lookup, so they are the only way those devices get a label.
TEST(DNSParserTest, ParsesPtrAnswersForReverseLookups) {
    std::vector<uint8_t> dns;
    appendU16(dns, 0x4321); // Transaction ID
    appendU16(dns, 0x8180); // Standard response
    appendU16(dns, 1);      // question count
    appendU16(dns, 1);      // answer count
    appendU16(dns, 0);
    appendU16(dns, 0);
    appendDnsName(dns, "1.1.168.192.in-addr.arpa");
    appendU16(dns, 12); // QTYPE = PTR
    appendU16(dns, 1);  // QCLASS = IN

    appendDnsName(dns, "1.1.168.192.in-addr.arpa");
    appendU16(dns, 12); // PTR
    appendU16(dns, 1);  // IN
    appendU32BE(dns, 300);
    std::vector<uint8_t> target;
    appendDnsName(target, "router.local");
    appendU16(dns, static_cast<uint16_t>(target.size()));
    dns.insert(dns.end(), target.begin(), target.end());

    std::vector<uint8_t> storage;
    const auto raw = wrapDnsResponse(storage, dns);
    const auto response = core::DNSParser::parseResponse(raw);

    ASSERT_TRUE(response.has_value());
    ASSERT_EQ(response->answers.size(), 1u);
    EXPECT_EQ(response->answers[0].type, core::DNSRecordType::PTR);
    EXPECT_EQ(response->answers[0].value, "router.local");

    const auto address = core::DNSParser::reverseNameToAddress(response->answers[0].name);
    ASSERT_TRUE(address.has_value());
    EXPECT_EQ(*address, "192.168.1.1");
}

// An HTTPS record advertising "ech" means the SNI of the next connection will be
// encrypted, so SNI-based identification is about to stop working for that host.
TEST(DNSParserTest, DetectsEncryptedClientHelloInHttpsRecord) {
    std::vector<uint8_t> rdata;
    appendU16(rdata, 1);      // SvcPriority
    rdata.push_back(0x00);    // TargetName = "." (same as owner)
    appendU16(rdata, 5);      // SvcParamKey = ech
    appendU16(rdata, 4);      // value length
    rdata.insert(rdata.end(), {0xAA, 0xBB, 0xCC, 0xDD});

    std::vector<uint8_t> dns;
    appendU16(dns, 0x5555);
    appendU16(dns, 0x8180);
    appendU16(dns, 1);
    appendU16(dns, 1);
    appendU16(dns, 0);
    appendU16(dns, 0);
    appendDnsName(dns, "crypto.example.com");
    appendU16(dns, 65); // QTYPE = HTTPS
    appendU16(dns, 1);

    appendDnsName(dns, "crypto.example.com");
    appendU16(dns, 65); // HTTPS
    appendU16(dns, 1);  // IN
    appendU32BE(dns, 300);
    appendU16(dns, static_cast<uint16_t>(rdata.size()));
    dns.insert(dns.end(), rdata.begin(), rdata.end());

    std::vector<uint8_t> storage;
    const auto raw = wrapDnsResponse(storage, dns);
    const auto response = core::DNSParser::parseResponse(raw);

    ASSERT_TRUE(response.has_value());
    EXPECT_TRUE(response->encryptedClientHelloAdvertised);
    ASSERT_EQ(response->answers.size(), 1u);
    EXPECT_EQ(response->answers[0].type, core::DNSRecordType::HTTPS);
}

TEST(DNSParserTest, ParsesDnsOverIPv6Transport) {
    std::vector<uint8_t> dns;
    appendU16(dns, 0x0001);
    appendU16(dns, 0x8180);
    appendU16(dns, 1);
    appendU16(dns, 1);
    appendU16(dns, 0);
    appendU16(dns, 0);
    appendDnsName(dns, "v6.example.com");
    appendU16(dns, 1);
    appendU16(dns, 1);
    appendDnsName(dns, "v6.example.com");
    appendU16(dns, 1);
    appendU16(dns, 1);
    appendU32BE(dns, 60);
    appendU16(dns, 4);
    dns.insert(dns.end(), {203, 0, 113, 42});

    const std::vector<uint8_t> source(16, 0x11);
    const std::vector<uint8_t> destination(16, 0x22);
    std::vector<uint8_t> packet;
    appendEthernetHeader(packet, 0x86DD);
    appendIPv6Header(packet, static_cast<uint16_t>(8 + dns.size()), 17, source, destination);
    appendUdpHeader(packet, 53, 53000, static_cast<uint16_t>(dns.size()));
    packet.insert(packet.end(), dns.begin(), dns.end());

    const core::PacketData raw(1, static_cast<uint32_t>(packet.size()),
        static_cast<uint32_t>(packet.size()), packet.data());
    const auto response = core::DNSParser::parseResponse(raw);

    ASSERT_TRUE(response.has_value());
    ASSERT_EQ(response->answers.size(), 1u);
    EXPECT_EQ(response->answers[0].value, "203.0.113.42");
}

// ---------------------------------------------------------------------------
// Canonical flow keying
// ---------------------------------------------------------------------------

namespace {
    core::ParsedPacket makeFlowPacket(const std::string& srcIP, uint16_t srcPort,
        const std::string& dstIP, uint16_t dstPort, uint32_t length, int64_t timestamp) {
        core::ParsedPacket packet;
        packet.timestamp = timestamp;
        packet.srcIP = srcIP;
        packet.dstIP = dstIP;
        packet.srcPort = srcPort;
        packet.dstPort = dstPort;
        packet.protocol = "UDP";
        packet.length = length;
        return packet;
    }
}

// Both endpoints ephemeral (WebRTC, BitTorrent, game traffic): neither port looks
// like a server, so the two directions must still collapse into one flow.
TEST(FlowAggregatorTest, CollapsesPeerToPeerFlowWithTwoEphemeralPorts) {
    constexpr int64_t start = 1'700'000'000'000'000;
    const auto outbound = makeFlowPacket("192.168.1.10", 54321, "203.0.113.5", 61234, 100, start);
    const auto inbound = makeFlowPacket("203.0.113.5", 61234, "192.168.1.10", 54321, 250, start + 1000);

    core::FlowAggregator flows;
    flows.update(outbound);
    flows.update(inbound);
    const auto snapshot = flows.snapshot(start + 500'000);

    ASSERT_EQ(snapshot.size(), 1u) << "both directions must share one canonical flow";
    const auto& flow = snapshot.front();
    EXPECT_EQ(flow.packets, 2u);
    EXPECT_EQ(flow.bytesUp, 100u);
    EXPECT_EQ(flow.bytesDown, 250u);
    EXPECT_TRUE(core::FlowAggregator::matches(outbound, flow.key));
    EXPECT_TRUE(core::FlowAggregator::matches(inbound, flow.key));
}

TEST(FlowAggregatorTest, KeepsDistinctPeerToPeerPortPairsSeparate) {
    constexpr int64_t start = 1'700'000'000'000'000;
    // Same host pair, two simultaneous conversations on different ports. Without
    // srcPort in the key these would collide into a single flow.
    core::FlowAggregator flows;
    flows.update(makeFlowPacket("192.168.1.10", 54321, "203.0.113.5", 61234, 100, start));
    flows.update(makeFlowPacket("192.168.1.10", 54322, "203.0.113.5", 61235, 100, start));

    EXPECT_EQ(flows.snapshot(start + 1000).size(), 2u);
}

TEST(FlowAggregatorTest, PeerToPeerKeyIsIndependentOfObservationOrder) {
    constexpr int64_t start = 1'700'000'000'000'000;
    const auto outbound = makeFlowPacket("192.168.1.10", 54321, "203.0.113.5", 61234, 100, start);
    const auto inbound = makeFlowPacket("203.0.113.5", 61234, "192.168.1.10", 54321, 100, start);

    const auto keyFromOutbound = core::FlowAggregator::keyFor(outbound);
    const auto keyFromInbound = core::FlowAggregator::keyFor(inbound);
    ASSERT_TRUE(keyFromOutbound.has_value());
    ASSERT_TRUE(keyFromInbound.has_value());
    EXPECT_EQ(*keyFromOutbound, *keyFromInbound);

    EXPECT_FALSE(core::FlowAggregator::isDownstream(outbound, *keyFromOutbound));
    EXPECT_TRUE(core::FlowAggregator::isDownstream(inbound, *keyFromOutbound));
}

// ---------------------------------------------------------------------------
// End-to-end: a capture file driven through the same pipeline the UI runs
// ---------------------------------------------------------------------------

namespace {
    // Mirrors GuiLayer::processQueue: parse, recover split ClientHellos, feed the
    // hostname cache from DNS, and aggregate flows.
    struct Pipeline {
        core::HostnameCache hostnames;
        core::FlowAggregator flows;
        core::TlsReassembler tls;
        core::QuicTracker quic;
        std::vector<core::ParsedPacket> parsedPackets;

        void consume(const core::PacketData& raw) {
            auto parsed = core::ProtocolParser::parse(raw);

            if (parsed.sni.empty() && parsed.payloadLength > 0
                && parsed.payloadOffset < raw.payload.size()) {
                const uint8_t* payload = raw.payload.data() + parsed.payloadOffset;
                const size_t length = std::min(parsed.payloadLength,
                    raw.payload.size() - parsed.payloadOffset);
                std::optional<std::string> recovered;
                if (parsed.protocol == "TCP") {
                    recovered = tls.feed(parsed, payload, length);
                } else if (parsed.protocol == "UDP"
                    && core::QuicParser::looksLikeLongHeader(payload, length)) {
                    recovered = quic.feed(payload, length, parsed.timestamp);
                }
                if (recovered) parsed.sni = *recovered;
            }

            if (const auto dns = core::DNSParser::parseResponse(raw, parsed)) {
                for (const auto& answer : dns->answers) {
                    if (answer.type == core::DNSRecordType::A) {
                        hostnames.store(answer.value,
                            dns->queryName.empty() ? answer.name : dns->queryName);
                        flows.setHostnameForAddress(answer.value,
                            dns->queryName.empty() ? answer.name : dns->queryName);
                    } else if (answer.type == core::DNSRecordType::PTR) {
                        if (const auto address = core::DNSParser::reverseNameToAddress(answer.name)) {
                            hostnames.store(*address, answer.value);
                            flows.setHostnameForAddress(*address, answer.value);
                        }
                    }
                }
            }

            std::string hostname;
            if (!parsed.sni.empty())            hostname = parsed.sni;
            else if (!parsed.hostname.empty())  hostname = parsed.hostname;
            flows.update(parsed, hostname);
            parsedPackets.push_back(std::move(parsed));
        }
    };

    std::vector<uint8_t> greWrappedDnsPacket() {
        std::vector<uint8_t> inner;
        appendIPv4Header(inner, 28, 17, {192, 168, 1, 5}, {8, 8, 4, 4});
        appendUdpHeader(inner, 40000, 53, 0);

        std::vector<uint8_t> packet;
        appendEthernetHeader(packet, 0x0800);
        appendIPv4Header(packet, static_cast<uint16_t>(20 + 4 + inner.size()), 47, {10, 0, 0, 1}, {10, 0, 0, 2});
        appendU16(packet, 0x0000);
        appendU16(packet, 0x0800);
        packet.insert(packet.end(), inner.begin(), inner.end());
        return packet;
    }

    std::vector<uint8_t> httpRequestPacket() {
        const auto request = makeHttpRequest("www.example.com");
        std::vector<uint8_t> packet;
        appendEthernetHeader(packet, 0x0800);
        appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + request.size()), 6,
            {192, 168, 1, 10}, {93, 184, 216, 34});
        appendTcpHeader(packet, 50200, 80, 1, 0x18);
        packet.insert(packet.end(), request.begin(), request.end());
        return packet;
    }

    // The ClientHello is split across two TCP segments on a non-standard port —
    // both of the things that used to lose the SNI, at once.
    std::vector<std::vector<uint8_t>> splitTlsPacketsOnPort8443() {
        const auto tls = makeTlsClientHello("split.internal.example");
        const size_t half = tls.size() / 2;
        std::vector<std::vector<uint8_t>> result;

        for (int segment = 0; segment < 2; ++segment) {
            const size_t offset = segment == 0 ? 0 : half;
            const size_t length = segment == 0 ? half : tls.size() - half;
            std::vector<uint8_t> packet;
            appendEthernetHeader(packet, 0x0800);
            appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + length), 6,
                {192, 168, 1, 10}, {203, 0, 113, 20});
            appendTcpHeader(packet, 50300, 8443, static_cast<uint32_t>(1 + offset), 0x18);
            packet.insert(packet.end(), tls.begin() + static_cast<std::ptrdiff_t>(offset),
                tls.begin() + static_cast<std::ptrdiff_t>(offset + length));
            result.push_back(std::move(packet));
        }
        return result;
    }
}

TEST_F(OfflinePcapTest, EndToEndCaptureSurfacesTunnelsHttpAndSplitTls) {
    std::vector<std::vector<uint8_t>> packets;
    packets.push_back(greWrappedDnsPacket());
    packets.push_back(httpRequestPacket());
    for (auto& segment : splitTlsPacketsOnPort8443()) packets.push_back(std::move(segment));

    const auto fixture = fixtureDirectory / "end-to-end.pcap";
    writePcapMulti(fixture, packets);

    core::PacketQueue queue;
    capture::CaptureEngine capture(queue);
    ASSERT_TRUE(capture.openFile(fixture.string()));

    Pipeline pipeline;
    while (auto raw = queue.try_pop()) pipeline.consume(*raw);
    ASSERT_EQ(pipeline.parsedPackets.size(), 4u);

    // 1. The GRE tunnel is transparent: the inner conversation is what shows.
    const auto& tunnelled = pipeline.parsedPackets[0];
    EXPECT_EQ(tunnelled.tunnel, "GRE");
    EXPECT_EQ(tunnelled.outerSrcIP, "10.0.0.1");
    EXPECT_EQ(tunnelled.srcIP, "192.168.1.5");
    EXPECT_EQ(tunnelled.service, "DNS");

    // 2. Cleartext HTTP yields a hostname with no DNS involved at all.
    const auto& http = pipeline.parsedPackets[1];
    EXPECT_EQ(http.hostname, "www.example.com");
    EXPECT_EQ(http.info, "GET /index.html HTTP/1.1");

    // 3. The split ClientHello on port 8443 resolves on the second segment.
    EXPECT_TRUE(pipeline.parsedPackets[2].sni.empty());
    EXPECT_EQ(pipeline.parsedPackets[3].sni, "split.internal.example");

    // 4. Each conversation became exactly one flow, named by what we learned.
    const auto flows = pipeline.flows.snapshot(1'700'000'000'000'000 + 10'000'000);
    ASSERT_EQ(flows.size(), 3u);

    const auto findFlow = [&](const std::string& dstIP) -> const core::Flow* {
        for (const auto& flow : flows) if (flow.key.dstIP == dstIP) return &flow;
        return nullptr;
    };
    const core::Flow* dnsFlow = findFlow("8.8.4.4");
    const core::Flow* httpFlow = findFlow("93.184.216.34");
    const core::Flow* tlsFlow = findFlow("203.0.113.20");
    ASSERT_NE(dnsFlow, nullptr);
    ASSERT_NE(httpFlow, nullptr);
    ASSERT_NE(tlsFlow, nullptr);

    EXPECT_EQ(dnsFlow->key.srcIP, "192.168.1.5") << "flow keyed on inner, not tunnel, endpoints";
    EXPECT_EQ(httpFlow->hostname, "www.example.com");
    EXPECT_EQ(tlsFlow->hostname, "split.internal.example");
    EXPECT_EQ(tlsFlow->packets, 2u) << "both segments belong to one flow";
}

TEST(FlowAggregatorTest, SetHostnameForAddressMatchesEitherEndpoint) {
    constexpr int64_t start = 1'700'000'000'000'000;
    core::FlowAggregator flows;
    // Inbound from a LAN device: the canonical source is the remote peer, so a
    // reverse-DNS answer for it must still land on the flow.
    flows.update(makeFlowPacket("192.168.1.50", 55000, "192.168.1.10", 55001, 100, start));
    flows.setHostnameForAddress("192.168.1.50", "printer.local");

    const auto snapshot = flows.snapshot(start + 1000);
    ASSERT_EQ(snapshot.size(), 1u);
    EXPECT_EQ(snapshot.front().hostname, "printer.local");
}

TEST(PacketQueueTest, ConcurrentProducerConsumerDeliversAllPackets) {
    constexpr int producerCount = 4;
    constexpr int packetsPerProducer = 500;
    constexpr int totalPackets = producerCount * packetsPerProducer;

    core::PacketQueue queue(static_cast<size_t>(totalPackets * 2));
    std::atomic<int> consumed{0};
    std::atomic<bool> done{false};

    std::thread consumer([&] {
        while (!done.load() || !queue.empty()) {
            if (auto packet = queue.try_pop()) consumed.fetch_add(1);
            else std::this_thread::yield();
        }
    });

    std::vector<std::thread> producers;
    producers.reserve(producerCount);
    for (int p = 0; p < producerCount; ++p) {
        producers.emplace_back([&, p] {
            for (int i = 0; i < packetsPerProducer; ++i) {
                queue.push(makeNumberedPacket(p * packetsPerProducer + i + 1));
            }
        });
    }
    for (auto& producer : producers) producer.join();
    done.store(true);
    consumer.join();

    EXPECT_EQ(consumed.load(), totalPackets);
    EXPECT_EQ(queue.droppedPackets(), 0u);
}
