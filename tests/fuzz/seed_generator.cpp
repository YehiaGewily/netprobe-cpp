#include "PacketBuilders.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

    void writeSeed(const std::filesystem::path& dir, const std::string& name,
                   const std::vector<uint8_t>& bytes) {
        const auto path = dir / name;
        std::ofstream out(path, std::ios::binary);
        if (!out) {
            std::cerr << "Failed to open " << path.string() << " for writing\n";
            return;
        }
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    std::vector<uint8_t> tlsClientHelloPacket() {
        const auto tls = test::makeTlsClientHello("example.com");
        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + tls.size()), 6,
            {192, 168, 1, 10}, {93, 184, 216, 34});
        test::appendU16(packet, 50123);
        test::appendU16(packet, 443);
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x18, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00});
        packet.insert(packet.end(), tls.begin(), tls.end());
        return packet;
    }

    std::vector<uint8_t> dnsQueryPacket() {
        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, 28, 17, {10, 0, 0, 5}, {8, 8, 8, 8});
        test::appendU16(packet, 53000);
        test::appendU16(packet, 53);
        packet.insert(packet.end(), {0x00, 0x08, 0x00, 0x00});
        return packet;
    }

    std::vector<uint8_t> dnsResponsePacket() {
        std::vector<uint8_t> dns;
        test::appendU16(dns, 0x1234);
        test::appendU16(dns, 0x8180);
        test::appendU16(dns, 1);
        test::appendU16(dns, 1);
        test::appendU16(dns, 0);
        test::appendU16(dns, 0);
        test::appendDnsName(dns, "example.com");
        test::appendU16(dns, 1);
        test::appendU16(dns, 1);
        test::appendDnsName(dns, "example.com");
        test::appendU16(dns, 1);
        test::appendU16(dns, 1);
        test::appendU32BE(dns, 60);
        test::appendU16(dns, 4);
        dns.insert(dns.end(), {93, 184, 216, 34});

        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, static_cast<uint16_t>(20 + 8 + dns.size()), 17,
            {8, 8, 8, 8}, {192, 168, 1, 10});
        test::appendU16(packet, 53);
        test::appendU16(packet, 53000);
        test::appendU16(packet, static_cast<uint16_t>(8 + dns.size()));
        test::appendU16(packet, 0);
        packet.insert(packet.end(), dns.begin(), dns.end());
        return packet;
    }

    std::vector<uint8_t> arpRequestPacket() {
        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0806);
        test::appendU16(packet, 1);
        test::appendU16(packet, 0x0800);
        packet.insert(packet.end(), {6, 4});
        test::appendU16(packet, 1);
        packet.insert(packet.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 192, 168, 1, 10});
        packet.insert(packet.end(), 6, 0x00);
        packet.insert(packet.end(), {192, 168, 1, 1});
        return packet;
    }

    std::vector<uint8_t> ipv6UdpPacket() {
        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x86DD);
        // IPv6 header: version=6, traffic class=0, flow label=0, payload length, next header (UDP=17), hop limit
        packet.insert(packet.end(), {0x60, 0x00, 0x00, 0x00});
        test::appendU16(packet, 12);          // payload length (UDP header + 4 byte payload)
        packet.push_back(17);                 // next header: UDP
        packet.push_back(64);                 // hop limit
        // src + dst IPv6 (16 bytes each)
        for (int i = 0; i < 16; ++i) packet.push_back(static_cast<uint8_t>(0x20 + i));
        for (int i = 0; i < 16; ++i) packet.push_back(static_cast<uint8_t>(0x30 + i));
        // UDP header + tiny payload
        test::appendU16(packet, 5353);
        test::appendU16(packet, 5353);
        test::appendU16(packet, 12);
        test::appendU16(packet, 0);
        packet.insert(packet.end(), {0xDE, 0xAD, 0xBE, 0xEF});
        return packet;
    }

}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <output-directory>\n";
        return 1;
    }
    const std::filesystem::path outputDir = argv[1];
    std::error_code ec;
    std::filesystem::create_directories(outputDir, ec);
    if (ec) {
        std::cerr << "Failed to create directory " << outputDir.string()
                  << ": " << ec.message() << "\n";
        return 1;
    }

    writeSeed(outputDir, "tls_client_hello.bin", tlsClientHelloPacket());
    writeSeed(outputDir, "dns_query.bin", dnsQueryPacket());
    writeSeed(outputDir, "dns_response.bin", dnsResponsePacket());
    writeSeed(outputDir, "arp_request.bin", arpRequestPacket());
    writeSeed(outputDir, "ipv6_udp.bin", ipv6UdpPacket());
    size_t seedCount = 5;

    // Adversarial shapes shared with tests/malformed_test.cpp. Handing these
    // to libFuzzer as starting points is far cheaper than waiting for it to
    // rediscover, byte by byte, that a length field can exceed its buffer.
    for (const auto& testCase : test::malformed::allCases()) {
        if (testCase.bytes.empty()) continue; // an empty file is not a useful seed
        std::string filename = "malformed_" + testCase.name + ".bin";
        std::replace(filename.begin(), filename.end(), '-', '_');
        writeSeed(outputDir, filename, testCase.bytes);
        ++seedCount;
    }

    std::cout << "Wrote " << seedCount << " seed packets to " << outputDir.string() << "\n";
    return 0;
}
