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

} // namespace test
