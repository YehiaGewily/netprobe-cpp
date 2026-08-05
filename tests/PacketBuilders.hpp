#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Wire-format constructors for synthetic Ethernet/IPv4/DNS/TLS packets.
// Shared between the unit tests (which compare parsed output against expected
// values) and the fuzz seed generator (which writes them out as a starting
// corpus for libFuzzer).
namespace test {

    inline void appendU16(std::vector<uint8_t>& bytes, uint16_t value) {
        bytes.push_back(static_cast<uint8_t>(value >> 8));
        bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    inline void appendU32LE(std::vector<uint8_t>& bytes, uint32_t value) {
        bytes.push_back(static_cast<uint8_t>(value & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    }

    inline void appendU32BE(std::vector<uint8_t>& bytes, uint32_t value) {
        bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    inline void appendDnsName(std::vector<uint8_t>& bytes, const std::string& name) {
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

    inline void appendEthernetHeader(std::vector<uint8_t>& bytes, uint16_t etherType) {
        bytes.insert(bytes.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
        bytes.insert(bytes.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB});
        appendU16(bytes, etherType);
    }

    inline void appendIPv4Header(std::vector<uint8_t>& bytes, uint16_t totalLength, uint8_t protocol,
        const std::vector<uint8_t>& source, const std::vector<uint8_t>& destination) {
        bytes.insert(bytes.end(), {0x45, 0x00});
        appendU16(bytes, totalLength);
        bytes.insert(bytes.end(), {0x00, 0x01, 0x40, 0x00, 64, protocol, 0x00, 0x00});
        bytes.insert(bytes.end(), source.begin(), source.end());
        bytes.insert(bytes.end(), destination.begin(), destination.end());
    }

    // Minimal 20-byte TCP header. `flags` uses the wire bit layout
    // (0x02 SYN, 0x10 ACK, 0x18 PSH|ACK).
    inline void appendTcpHeader(std::vector<uint8_t>& bytes, uint16_t sourcePort,
        uint16_t destinationPort, uint32_t sequence, uint8_t flags) {
        appendU16(bytes, sourcePort);
        appendU16(bytes, destinationPort);
        appendU32BE(bytes, sequence);
        appendU32BE(bytes, 0);          // acknowledgement number
        bytes.push_back(0x50);          // data offset = 5 words, no options
        bytes.push_back(flags);
        appendU16(bytes, 0xFFFF);       // window
        appendU16(bytes, 0x0000);       // checksum
        appendU16(bytes, 0x0000);       // urgent pointer
    }

    inline void appendUdpHeader(std::vector<uint8_t>& bytes, uint16_t sourcePort,
        uint16_t destinationPort, uint16_t payloadLength) {
        appendU16(bytes, sourcePort);
        appendU16(bytes, destinationPort);
        appendU16(bytes, static_cast<uint16_t>(8 + payloadLength));
        appendU16(bytes, 0x0000); // checksum
    }

    // 40-byte fixed IPv6 header.
    inline void appendIPv6Header(std::vector<uint8_t>& bytes, uint16_t payloadLength,
        uint8_t nextHeader, const std::vector<uint8_t>& source, const std::vector<uint8_t>& destination) {
        bytes.insert(bytes.end(), {0x60, 0x00, 0x00, 0x00});
        appendU16(bytes, payloadLength);
        bytes.push_back(nextHeader);
        bytes.push_back(64); // hop limit
        bytes.insert(bytes.end(), source.begin(), source.end());
        bytes.insert(bytes.end(), destination.begin(), destination.end());
    }

    inline std::vector<uint8_t> makeHttpRequest(const std::string& host, const std::string& path = "/index.html") {
        const std::string text = "GET " + path + " HTTP/1.1\r\n"
            "User-Agent: netprobe-test\r\n"
            "Host: " + host + "\r\n"
            "Accept: */*\r\n\r\n";
        return std::vector<uint8_t>(text.begin(), text.end());
    }

    inline std::vector<uint8_t> makeTlsClientHello(const std::string& hostname) {
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

    // ---------------------------------------------------------------------
    // Adversarial inputs.
    //
    // Wire-format constructors that lie about their own structure: headers
    // claiming lengths the buffer does not contain, chains that run off the
    // end, counts that exceed the data present. These are the shapes that
    // crash capture tools in production, and they are shared with the fuzz
    // seed corpus so libFuzzer starts from them rather than rediscovering
    // them byte by byte.
    // ---------------------------------------------------------------------
    namespace malformed {

        struct Case {
            std::string name;
            std::vector<uint8_t> bytes;

            // The degraded outcome this input must produce. Pinning it is the
            // point: a parser that walks off the end of a packet and returns a
            // plausible-looking result is worse than one that gives up, and
            // only an expected value catches the difference.
            //
            // Empty expectedProtocol means "unconstrained" — used where more
            // than one answer is defensible.
            std::string expectedProtocol;
            // True when the transport payload cannot be located, so the
            // payload window must stay empty.
            bool expectNoPayload = false;
            // Most fixtures destroy the framing badly enough that no server
            // name can survive. A few corrupt exactly one length field while
            // leaving a well-formed ClientHello intact and reachable — there,
            // recovering the SNI is correct behaviour, not invention.
            bool expectNoSni = true;
        };

        // Offsets into an Ethernet + IPv4 frame.
        inline constexpr size_t kEthernetSize = 14;
        inline constexpr size_t kIPv4Offset = kEthernetSize;
        inline constexpr size_t kIPv4VersionIhl = kIPv4Offset;
        inline constexpr size_t kIPv4TotalLength = kIPv4Offset + 2;
        inline constexpr size_t kTcpOffset = kIPv4Offset + 20;
        inline constexpr size_t kTcpDataOffset = kTcpOffset + 12;

        inline std::vector<uint8_t> validTcpFrame(const std::vector<uint8_t>& payload) {
            std::vector<uint8_t> packet;
            appendEthernetHeader(packet, 0x0800);
            appendIPv4Header(packet, static_cast<uint16_t>(20 + 20 + payload.size()), 6,
                {192, 168, 1, 10}, {93, 184, 216, 34});
            appendTcpHeader(packet, 50000, 443, 1000, 0x18);
            packet.insert(packet.end(), payload.begin(), payload.end());
            return packet;
        }

        inline std::vector<uint8_t> validUdpFrame(const std::vector<uint8_t>& payload) {
            std::vector<uint8_t> packet;
            appendEthernetHeader(packet, 0x0800);
            appendIPv4Header(packet, static_cast<uint16_t>(20 + 8 + payload.size()), 17,
                {8, 8, 8, 8}, {192, 168, 1, 10});
            appendUdpHeader(packet, 53, 53000, static_cast<uint16_t>(payload.size()));
            packet.insert(packet.end(), payload.begin(), payload.end());
            return packet;
        }

        inline std::vector<uint8_t> truncatedTo(std::vector<uint8_t> bytes, size_t size) {
            if (bytes.size() > size) bytes.resize(size);
            return bytes;
        }

        // An IPv6 frame whose next-header chain is supplied verbatim, so a
        // caller can build chains that overrun or run long.
        inline std::vector<uint8_t> ipv6WithChain(uint8_t firstNextHeader,
            const std::vector<uint8_t>& chain) {
            std::vector<uint8_t> packet;
            appendEthernetHeader(packet, 0x86DD);
            appendIPv6Header(packet, static_cast<uint16_t>(chain.size()), firstNextHeader,
                {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});
            packet.insert(packet.end(), chain.begin(), chain.end());
            return packet;
        }

        // A TCP frame whose header claims `dataOffsetWords` 32-bit words and
        // carries `options` between the fixed header and the payload.
        inline std::vector<uint8_t> tcpFrameWithOptions(uint8_t dataOffsetWords,
            const std::vector<uint8_t>& options, const std::vector<uint8_t>& payload) {
            std::vector<uint8_t> packet;
            appendEthernetHeader(packet, 0x0800);
            appendIPv4Header(packet,
                static_cast<uint16_t>(20 + 20 + options.size() + payload.size()), 6,
                {192, 168, 1, 10}, {93, 184, 216, 34});
            appendTcpHeader(packet, 50000, 443, 1000, 0x18);
            // appendTcpHeader writes a fixed data offset of 5 words; override
            // it so the header can claim the option bytes that follow.
            packet[kTcpDataOffset] = static_cast<uint8_t>(dataOffsetWords << 4);
            packet.insert(packet.end(), options.begin(), options.end());
            packet.insert(packet.end(), payload.begin(), payload.end());
            return packet;
        }

        inline std::vector<Case> allCases() {
            std::vector<Case> cases;
            const auto add = [&cases](std::string name, std::vector<uint8_t> bytes,
                std::string expectedProtocol = {}, bool expectNoPayload = false,
                bool expectNoSni = true) {
                cases.push_back({std::move(name), std::move(bytes),
                    std::move(expectedProtocol), expectNoPayload, expectNoSni});
            };

            const auto tlsFrame = validTcpFrame(makeTlsClientHello("truncated.example.com"));
            const auto httpFrame = validTcpFrame(makeHttpRequest("truncated.example.com"));

            // --- Truncation at every layer boundary --------------------------
            // A zero-length capture is distinguishable from a truncated one:
            // there are no bytes to have been cut short.
            add("empty", {}, "Unknown", /*expectNoPayload=*/true);
            add("one-byte", {0x00}, "Truncated", /*expectNoPayload=*/true);
            // Below 34 bytes there is not a complete Ethernet + IPv4 header,
            // so no transport can be named and no payload located.
            for (const size_t size : {6u, 13u}) {
                add("tls-frame-truncated-to-" + std::to_string(size),
                    truncatedTo(tlsFrame, size), "Truncated", /*expectNoPayload=*/true);
            }
            // A complete Ethernet header but an incomplete IPv4 one: no
            // transport is nameable and no payload can be located.
            for (const size_t size : {14u, 15u, 20u, 33u}) {
                add("tls-frame-truncated-to-" + std::to_string(size),
                    truncatedTo(tlsFrame, size), {}, /*expectNoPayload=*/true);
            }
            // From here the headers are present but the payload is cut short;
            // more than one answer is defensible, so only sanity is asserted.
            for (const size_t size : {34u, 40u, 45u, 53u}) {
                add("tls-frame-truncated-to-" + std::to_string(size),
                    truncatedTo(tlsFrame, size));
            }
            add("http-frame-truncated-mid-payload", truncatedTo(httpFrame, 60));

            // --- IPv4 headers that lie --------------------------------------
            {
                auto packet = tlsFrame;
                packet[kIPv4VersionIhl] = 0x40; // IHL = 0, below the 20-byte minimum
                add("ipv4-ihl-zero", packet, "Unknown", /*expectNoPayload=*/true);
            }
            {
                auto packet = tlsFrame;
                packet[kIPv4VersionIhl] = 0x44; // IHL = 4 words = 16 bytes
                add("ipv4-ihl-below-minimum", packet, "Unknown", /*expectNoPayload=*/true);
            }
            {
                auto packet = tlsFrame;
                packet[kIPv4VersionIhl] = 0x4F; // IHL = 15 words = 60 bytes of options
                add("ipv4-ihl-claims-options-past-header", packet);
            }
            {
                auto packet = tlsFrame;
                packet[kIPv4TotalLength] = 0xFF; // total length far beyond the buffer
                packet[kIPv4TotalLength + 1] = 0xFF;
                add("ipv4-total-length-exceeds-buffer", packet, "TCP", /*expectNoPayload=*/false,
                    /*expectNoSni=*/false);
            }
            {
                auto packet = tlsFrame;
                packet[kIPv4TotalLength] = 0x00; // total length below the header size
                packet[kIPv4TotalLength + 1] = 0x08;
                add("ipv4-total-length-below-header", packet, "Unknown", /*expectNoPayload=*/true);
            }
            {
                auto packet = tlsFrame;
                packet[kIPv4VersionIhl] = 0x65; // version 6 in an IPv4 ethertype frame
                add("ipv4-version-mismatch", packet, "Unknown", /*expectNoPayload=*/true);
            }

            // --- TCP headers that lie ---------------------------------------
            {
                auto packet = tlsFrame;
                packet[kTcpDataOffset] = 0xF0; // data offset = 15 words = 60 bytes
                add("tcp-data-offset-past-payload", packet, "TCP");
            }
            {
                auto packet = tlsFrame;
                packet[kTcpDataOffset] = 0x00; // data offset = 0, below the 20-byte minimum
                add("tcp-data-offset-zero", packet, "TCP", /*expectNoPayload=*/true);
            }

            // --- TCP options that lie ---------------------------------------
            {
                // Option kind 2 (MSS) declaring length 0. A parser that walks
                // the option list by adding the declared length never advances
                // past this one: the classic infinite-loop bait.
                const std::vector<uint8_t> options = {0x02, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                add("tcp-option-length-zero",
                    tcpFrameWithOptions(8, options, {0xDE, 0xAD, 0xBE, 0xEF}));
            }
            {
                // Option kind 2 declaring 200 bytes inside a 12-byte option
                // area, so the option runs past the end of the header.
                const std::vector<uint8_t> options = {0x02, 0xC8, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                add("tcp-option-length-overruns-header",
                    tcpFrameWithOptions(8, options, {0xDE, 0xAD, 0xBE, 0xEF}));
            }
            {
                // A well-formed option area, as the control for the two above:
                // NOP, NOP, then a valid 10-byte timestamp option.
                std::vector<uint8_t> options = {0x01, 0x01, 0x08, 0x0A};
                options.resize(12, 0x00);
                add("tcp-valid-options",
                    tcpFrameWithOptions(8, options, {0xDE, 0xAD, 0xBE, 0xEF}), "TCP");
            }
            {
                // Data offset claims option bytes the frame does not contain.
                add("tcp-options-claimed-but-absent",
                    tcpFrameWithOptions(15, {}, {}), "TCP", /*expectNoPayload=*/true);
            }

            // --- UDP headers that lie ---------------------------------------
            {
                auto packet = validUdpFrame({0xDE, 0xAD, 0xBE, 0xEF});
                packet[kIPv4Offset + 20 + 4] = 0xFF; // UDP length beyond the buffer
                packet[kIPv4Offset + 20 + 5] = 0xFF;
                add("udp-length-exceeds-buffer", packet);
            }
            {
                auto packet = validUdpFrame({0xDE, 0xAD, 0xBE, 0xEF});
                packet[kIPv4Offset + 20 + 4] = 0x00; // UDP length below its own 8-byte header
                packet[kIPv4Offset + 20 + 5] = 0x02;
                add("udp-length-below-header", packet);
            }

            // --- IPv6 extension header chains -------------------------------
            {
                // Hop-by-hop -> routing -> fragment -> TCP, all well formed.
                std::vector<uint8_t> chain = {43, 0}; // hop-by-hop: next=routing, len=0 (8 bytes)
                chain.resize(8, 0x00);
                chain.insert(chain.end(), {44, 0});   // routing: next=fragment
                chain.resize(16, 0x00);
                chain.insert(chain.end(), {6, 0});    // fragment: next=TCP
                chain.resize(24, 0x00);
                add("ipv6-valid-extension-chain", ipv6WithChain(0, chain));
            }
            {
                // Hop-by-hop claiming 2048 bytes of options that are not there.
                const std::vector<uint8_t> chain = {6, 0xFF, 0, 0, 0, 0, 0, 0};
                add("ipv6-extension-length-past-packet", ipv6WithChain(0, chain));
            }
            {
                // A long but individually valid chain: the walk must terminate
                // because every step advances at least 8 bytes.
                std::vector<uint8_t> chain;
                constexpr int kLinks = 64;
                for (int link = 0; link < kLinks; ++link) {
                    chain.push_back(link + 1 == kLinks ? uint8_t{6} : uint8_t{0});
                    chain.push_back(0); // length 0 => this header occupies 8 bytes
                    chain.resize(chain.size() + 6, 0x00);
                }
                add("ipv6-long-extension-chain", ipv6WithChain(0, chain));
            }
            {
                // Destination-options header pointing at itself as the next
                // header, repeatedly. Terminates only because pos advances.
                std::vector<uint8_t> chain;
                for (int link = 0; link < 16; ++link) {
                    chain.push_back(60); // next header = destination options again
                    chain.push_back(0);
                    chain.resize(chain.size() + 6, 0x00);
                }
                add("ipv6-self-referential-extension-chain", ipv6WithChain(60, chain));
            }

            // --- DNS payloads that lie --------------------------------------
            {
                std::vector<uint8_t> dns;
                appendU16(dns, 0x1234);
                appendU16(dns, 0x8180);
                appendU16(dns, 1);
                appendU16(dns, 20); // claims 20 answers
                appendU16(dns, 0);
                appendU16(dns, 0);
                appendDnsName(dns, "www.example.com");
                appendU16(dns, 1);
                appendU16(dns, 1);
                add("dns-answer-count-exceeds-payload", validUdpFrame(dns));
            }
            {
                // A compression pointer that points back at itself.
                std::vector<uint8_t> dns;
                appendU16(dns, 0x1234);
                appendU16(dns, 0x8180);
                appendU16(dns, 1);
                appendU16(dns, 1);
                appendU16(dns, 0);
                appendU16(dns, 0);
                dns.insert(dns.end(), {0xC0, 0x0C}); // pointer to offset 12 == itself
                appendU16(dns, 1);
                appendU16(dns, 1);
                add("dns-self-referential-compression-pointer", validUdpFrame(dns));
            }
            {
                // A label whose length runs past the end of the payload.
                std::vector<uint8_t> dns;
                appendU16(dns, 0x1234);
                appendU16(dns, 0x8180);
                appendU16(dns, 1);
                appendU16(dns, 0);
                appendU16(dns, 0);
                appendU16(dns, 0);
                dns.push_back(0x3F); // 63-byte label with 3 bytes following
                dns.insert(dns.end(), {'a', 'b', 'c'});
                add("dns-label-runs-past-payload", validUdpFrame(dns));
            }
            {
                std::vector<uint8_t> dns;
                appendU16(dns, 0x1234);
                appendU16(dns, 0x8180);
                add("dns-truncated-mid-header", validUdpFrame(dns));
            }

            // --- TLS records that lie ---------------------------------------
            {
                // Record header announcing 64 KB with almost nothing behind it.
                std::vector<uint8_t> tls = {0x16, 0x03, 0x01, 0xFF, 0xFF, 0x01, 0x00, 0xFF, 0xFB};
                add("tls-record-length-exceeds-payload", validTcpFrame(tls));
            }
            {
                auto tls = makeTlsClientHello("half.example.com");
                tls.resize(tls.size() / 2);
                add("tls-client-hello-truncated", validTcpFrame(tls));
            }

            // --- QUIC long headers that lie ---------------------------------
            {
                // Long header, version 1, destination CID length 255.
                std::vector<uint8_t> quic = {0xC0, 0x00, 0x00, 0x00, 0x01, 0xFF};
                quic.resize(32, 0x41);
                add("quic-connection-id-length-exceeds-packet", validUdpFrame(quic));
            }
            {
                // Truncated part way through the version field.
                const std::vector<uint8_t> quic = {0xC0, 0x00, 0x00};
                add("quic-truncated-mid-version", validUdpFrame(quic));
            }
            {
                // Token length varint claiming an implausible size.
                std::vector<uint8_t> quic = {0xC0, 0x00, 0x00, 0x00, 0x01, 0x08};
                quic.resize(14, 0x42);       // 8-byte destination CID
                quic.push_back(0x00);        // source CID length 0
                quic.push_back(0xFF);        // token length varint, 8-byte form, huge
                quic.resize(quic.size() + 3, 0xFF);
                add("quic-token-length-exceeds-packet", validUdpFrame(quic));
            }

            return cases;
        }

    } // namespace malformed

} // namespace test
