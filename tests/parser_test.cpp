#include "capture/CaptureEngine.hpp"
#include "core/DNSParser.hpp"
#include "core/FlowAggregator.hpp"
#include "core/GeoIPResolver.hpp"
#include "core/HostnameCache.hpp"
#include "core/PacketQueue.hpp"
#include "core/ProtocolParser.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

    void appendU16(std::vector<uint8_t>& bytes, uint16_t value) {
        bytes.push_back(static_cast<uint8_t>(value >> 8));
        bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    void appendU32LE(std::vector<uint8_t>& bytes, uint32_t value) {
        bytes.push_back(static_cast<uint8_t>(value & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    }

    void appendU32BE(std::vector<uint8_t>& bytes, uint32_t value) {
        bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    void appendDnsName(std::vector<uint8_t>& bytes, const std::string& name) {
        size_t labelStart = 0;
        while (labelStart < name.size()) {
            const size_t labelEnd = name.find('.', labelStart);
            const size_t labelLength = (labelEnd == std::string::npos ? name.size() : labelEnd) - labelStart;
            bytes.push_back(static_cast<uint8_t>(labelLength));
            bytes.insert(bytes.end(), name.begin() + static_cast<std::ptrdiff_t>(labelStart),
                name.begin() + static_cast<std::ptrdiff_t>(labelStart + labelLength));
            if (labelEnd == std::string::npos) break;
            labelStart = labelEnd + 1;
        }
        bytes.push_back(0x00);
    }

    void appendEthernetHeader(std::vector<uint8_t>& bytes, uint16_t etherType) {
        bytes.insert(bytes.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
        bytes.insert(bytes.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB});
        appendU16(bytes, etherType);
    }

    void appendIPv4Header(std::vector<uint8_t>& bytes, uint16_t totalLength, uint8_t protocol,
        const std::vector<uint8_t>& source, const std::vector<uint8_t>& destination) {
        bytes.insert(bytes.end(), {0x45, 0x00});
        appendU16(bytes, totalLength);
        bytes.insert(bytes.end(), {0x00, 0x01, 0x40, 0x00, 64, protocol, 0x00, 0x00});
        bytes.insert(bytes.end(), source.begin(), source.end());
        bytes.insert(bytes.end(), destination.begin(), destination.end());
    }

    std::vector<uint8_t> makeTlsClientHello(const std::string& hostname) {
        std::vector<uint8_t> body = {0x03, 0x03};
        body.insert(body.end(), 32, 0x00); // ClientHello random
        body.push_back(0x00); // Empty session ID
        appendU16(body, 2);
        appendU16(body, 0x1301);
        body.insert(body.end(), {0x01, 0x00}); // Null compression

        std::vector<uint8_t> extensions;
        appendU16(extensions, 0x0000); // Server Name Indication
        appendU16(extensions, static_cast<uint16_t>(5 + hostname.size()));
        appendU16(extensions, static_cast<uint16_t>(3 + hostname.size()));
        extensions.push_back(0x00); // host_name
        appendU16(extensions, static_cast<uint16_t>(hostname.size()));
        extensions.insert(extensions.end(), hostname.begin(), hostname.end());
        appendU16(body, static_cast<uint16_t>(extensions.size()));
        body.insert(body.end(), extensions.begin(), extensions.end());

        std::vector<uint8_t> record = {0x16, 0x03, 0x01};
        appendU16(record, static_cast<uint16_t>(4 + body.size()));
        record.push_back(0x01); // ClientHello handshake
        record.push_back(static_cast<uint8_t>(body.size() >> 16));
        record.push_back(static_cast<uint8_t>(body.size() >> 8));
        record.push_back(static_cast<uint8_t>(body.size()));
        record.insert(record.end(), body.begin(), body.end());
        return record;
    }

    void writePcap(const std::filesystem::path& path, const std::vector<uint8_t>& packet) {
        std::vector<uint8_t> bytes;
        // Little-endian PCAP global header, Ethernet link type.
        appendU32LE(bytes, 0xA1B2C3D4);
        bytes.insert(bytes.end(), {0x02, 0x00, 0x04, 0x00});
        appendU32LE(bytes, 0); // thiszone
        appendU32LE(bytes, 0); // sigfigs
        appendU32LE(bytes, 65535);
        appendU32LE(bytes, 1); // DLT_EN10MB

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
    EXPECT_EQ(packets[0].protocol, "Non-IPv4");
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
