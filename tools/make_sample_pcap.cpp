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

    const std::vector<uint8_t> kClientAddress = {192, 168, 1, 42};

    // 20-byte TCP header. test::appendTcpHeader hardcodes a zero
    // acknowledgement number, which would make the SYN-ACKs below wrong if
    // anyone opened this capture in Wireshark.
    void appendTcpHeader(std::vector<uint8_t>& packet, uint16_t sourcePort,
        uint16_t destinationPort, uint32_t sequence, uint32_t acknowledgement, uint8_t flags) {
        test::appendU16(packet, sourcePort);
        test::appendU16(packet, destinationPort);
        test::appendU32BE(packet, sequence);
        test::appendU32BE(packet, acknowledgement);
        packet.push_back(0x50);          // data offset = 5 words, no options
        packet.push_back(flags);
        test::appendU16(packet, 0xFFFF); // window
        test::appendU16(packet, 0x0000); // checksum
        test::appendU16(packet, 0x0000); // urgent pointer
    }

    std::vector<uint8_t> tcpSegment(const std::vector<uint8_t>& serverAddress,
        uint16_t clientPort, uint32_t sequence, uint32_t acknowledgement, uint8_t flags,
        bool fromServer, const std::vector<uint8_t>& payload = {}) {
        std::vector<uint8_t> packet;
        test::appendEthernetHeader(packet, 0x0800);
        test::appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + payload.size()), 6,
            fromServer ? serverAddress : kClientAddress,
            fromServer ? kClientAddress : serverAddress);
        appendTcpHeader(packet,
            fromServer ? uint16_t{443} : clientPort,
            fromServer ? clientPort : uint16_t{443},
            sequence, acknowledgement, flags);
        packet.insert(packet.end(), payload.begin(), payload.end());
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

}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <output.pcap>\n";
        return 1;
    }
    const std::filesystem::path output = argv[1];
    std::filesystem::create_directories(output.parent_path());

    // One resolvable site per connection. Each gets its own address and client
    // port so the capture yields three distinct flows, each matching the DNS
    // answer that precedes it — previously every ClientHello was addressed to
    // the same server regardless of the name it advertised, which collapsed
    // them into a single flow whose repeated sequence numbers read as
    // retransmissions.
    struct Site {
        std::string hostname;
        std::vector<uint8_t> address;
        uint16_t clientPort;
        uint32_t roundTripMicroseconds; // gap between SYN and SYN-ACK
    };
    const std::vector<Site> sites = {
        {"www.example.com",   {93, 184, 216, 34}, 50123, 12'000},
        {"api.github.com",    {140, 82, 121, 6},  50124, 38'000},
        {"cdn.netprobe.test", {52, 84, 100, 5},   50125,  6'500},
    };

    constexpr uint8_t kSyn = 0x02;
    constexpr uint8_t kSynAck = 0x12;
    constexpr uint8_t kPshAck = 0x18;

    std::vector<CapturedPacket> packets;
    const uint32_t t = 1700000000;
    uint32_t at = 0;
    const auto advance = [&at](uint32_t microseconds) { return at += microseconds; };

    packets.push_back({t, at, arpRequestPacket()});

    for (const auto& site : sites) {
        packets.push_back({t, advance(1'500), dnsQueryPacket(site.hostname)});
        packets.push_back({t, advance(2'700), dnsResponsePacket(site.hostname, site.address)});

        // A complete three-way handshake, so the flow reports an initial RTT.
        // The SYN consumes sequence 0, which is why the ClientHello starts at 1.
        packets.push_back({t, advance(900),
            tcpSegment(site.address, site.clientPort, 0, 0, kSyn, /*fromServer=*/false)});
        packets.push_back({t, advance(site.roundTripMicroseconds),
            tcpSegment(site.address, site.clientPort, 0, 1, kSynAck, /*fromServer=*/true)});
        packets.push_back({t, advance(1'200),
            tcpSegment(site.address, site.clientPort, 1, 1, kPshAck, /*fromServer=*/false,
                test::makeTlsClientHello(site.hostname))});
    }

    writePcap(output, packets);
    std::cout << "Wrote " << packets.size() << " packets to " << output.string() << "\n";
    return 0;
}
