#include "PacketBuilders.hpp"

#include "capture/CaptureEngine.hpp"
#include "core/DNSParser.hpp"
#include "core/FlowAggregator.hpp"
#include "core/GeoIPResolver.hpp"
#include "core/HostnameCache.hpp"
#include "core/PacketQueue.hpp"
#include "core/ProtocolParser.hpp"
#include "core/QuicParser.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

    using namespace test;

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
