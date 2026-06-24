// Emits data/sample.pcap — a tiny mixed-traffic capture used by NetProbe's
// first-run experience. Loading this file via File → Open PCAP exercises the
// full pipeline (DNS, TLS SNI, ARP, HTTPS over TCP/443) without needing
// elevated privileges for live capture.

#include "PacketBuilders.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

    struct CapturedPacket {
        uint32_t tsSec;
        uint32_t tsUsec;
        std::vector<uint8_t> bytes;
    };

    void writePcap(const std::filesystem::path& path, const std::vector<CapturedPacket>& packets) {
        std::vector<uint8_t> out;
        // Little-endian PCAP global header, Ethernet link type (DLT_EN10MB).
        test::appendU32LE(out, 0xA1B2C3D4);
        out.insert(out.end(), {0x02, 0x00, 0x04, 0x00}); // version_major=2, version_minor=4 (LE)
        test::appendU32LE(out, 0);     // thiszone
        test::appendU32LE(out, 0);     // sigfigs
        test::appendU32LE(out, 65535); // snaplen
        test::appendU32LE(out, 1);     // DLT_EN10MB

        for (const auto& pkt : packets) {
            test::appendU32LE(out, pkt.tsSec);
            test::appendU32LE(out, pkt.tsUsec);
            test::appendU32LE(out, static_cast<uint32_t>(pkt.bytes.size()));
            test::appendU32LE(out, static_cast<uint32_t>(pkt.bytes.size()));
            out.insert(out.end(), pkt.bytes.begin(), pkt.bytes.end());
        }

        std::ofstream f(path, std::ios::binary);
        if (!f) {
            std::cerr << "Cannot open " << path.string() << " for writing\n";
            return;
        }
        f.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    }

    std::vector<uint8_t> tlsClientHelloPacket(const std::string& sni) {
        const auto tls = test::makeTlsClientHello(sni);
        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + tls.size()), 6,
            {192, 168, 1, 42}, {93, 184, 216, 34});
        test::appendU16(packet, 50123);
        test::appendU16(packet, 443);
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x18, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00});
        packet.insert(packet.end(), tls.begin(), tls.end());
        return packet;
    }

    std::vector<uint8_t> dnsQueryPacket(const std::string& name) {
        std::vector<uint8_t> dns;
        test::appendU16(dns, 0xBEEF);
        test::appendU16(dns, 0x0100); // standard query, recursion desired
        test::appendU16(dns, 1);      // questions
        test::appendU16(dns, 0);
        test::appendU16(dns, 0);
        test::appendU16(dns, 0);
        test::appendDnsName(dns, name);
        test::appendU16(dns, 1);       // QTYPE A
        test::appendU16(dns, 1);       // QCLASS IN

        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, static_cast<uint16_t>(20 + 8 + dns.size()), 17,
            {192, 168, 1, 42}, {1, 1, 1, 1});
        test::appendU16(packet, 53000);
        test::appendU16(packet, 53);
        test::appendU16(packet, static_cast<uint16_t>(8 + dns.size()));
        test::appendU16(packet, 0);
        packet.insert(packet.end(), dns.begin(), dns.end());
        return packet;
    }

    std::vector<uint8_t> dnsResponsePacket(const std::string& name,
                                            const std::vector<uint8_t>& ipv4Answer) {
        std::vector<uint8_t> dns;
        test::appendU16(dns, 0xBEEF);
        test::appendU16(dns, 0x8180); // standard response, recursion available
        test::appendU16(dns, 1);
        test::appendU16(dns, 1);
        test::appendU16(dns, 0);
        test::appendU16(dns, 0);
        test::appendDnsName(dns, name);
        test::appendU16(dns, 1);
        test::appendU16(dns, 1);
        test::appendDnsName(dns, name);
        test::appendU16(dns, 1);
        test::appendU16(dns, 1);
        test::appendU32BE(dns, 300);
        test::appendU16(dns, 4);
        dns.insert(dns.end(), ipv4Answer.begin(), ipv4Answer.end());

        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, static_cast<uint16_t>(20 + 8 + dns.size()), 17,
            {1, 1, 1, 1}, {192, 168, 1, 42});
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
        packet.insert(packet.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 192, 168, 1, 42});
        packet.insert(packet.end(), 6, 0x00);
        packet.insert(packet.end(), {192, 168, 1, 1});
        return packet;
    }

    std::vector<uint8_t> tcpSynPacket() {
        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, static_cast<uint16_t>(20 + 20), 6,
            {192, 168, 1, 42}, {93, 184, 216, 34});
        test::appendU16(packet, 50123);
        test::appendU16(packet, 443);
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00});
        return packet;
    }

}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <output.pcap>\n";
        return 1;
    }
    const std::filesystem::path output = argv[1];
    std::filesystem::create_directories(output.parent_path());

    std::vector<CapturedPacket> packets;
    uint32_t t = 1700000000;
    packets.push_back({t,     0, arpRequestPacket()});
    packets.push_back({t,  1500, dnsQueryPacket("www.example.com")});
    packets.push_back({t,  4200, dnsResponsePacket("www.example.com", {93, 184, 216, 34})});
    packets.push_back({t,  5100, tcpSynPacket()});
    packets.push_back({t,  6300, tlsClientHelloPacket("www.example.com")});
    packets.push_back({t,  8700, dnsQueryPacket("api.github.com")});
    packets.push_back({t, 12100, dnsResponsePacket("api.github.com", {140, 82, 121, 6})});
    packets.push_back({t, 13400, tlsClientHelloPacket("api.github.com")});
    packets.push_back({t, 19000, dnsQueryPacket("cdn.netprobe.test")});
    packets.push_back({t, 21300, dnsResponsePacket("cdn.netprobe.test", {52, 84, 100, 5})});
    packets.push_back({t, 22700, tlsClientHelloPacket("cdn.netprobe.test")});

    writePcap(output, packets);
    std::cout << "Wrote " << packets.size() << " packets to " << output.string() << "\n";
    return 0;
}
