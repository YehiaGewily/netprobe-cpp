#include "core/DNSParser.hpp"
#include "core/NetworkPlatform.hpp"

#include <algorithm>
#include <cstdint>

namespace core {
    namespace {
        constexpr uint16_t ethernetIPv4 = 0x0800;
        constexpr uint16_t ethernetIPv6 = 0x86DD;
        constexpr uint16_t vlanTag = 0x8100;
        constexpr uint16_t providerVlanTag = 0x88A8;
        constexpr uint16_t doubleVlanTag = 0x9100;
        constexpr uint16_t dnsPort = 53;
        constexpr uint16_t mdnsPort = 5353;
        constexpr uint16_t dnsClassInternet = 1;

        uint16_t readU16(const uint8_t* bytes) {
            return static_cast<uint16_t>(bytes[0]) << 8 | bytes[1];
        }

        uint32_t readU32(const uint8_t* bytes) {
            return (static_cast<uint32_t>(bytes[0]) << 24)
                | (static_cast<uint32_t>(bytes[1]) << 16)
                | (static_cast<uint32_t>(bytes[2]) << 8)
                | bytes[3];
        }

        std::optional<std::string> readName(const uint8_t* data, size_t size, size_t& position) {
            std::string name;
            size_t cursor = position;
            size_t pointerCount = 0;
            bool followedPointer = false;

            while (cursor < size) {
                const uint8_t labelLength = data[cursor];
                if (labelLength == 0) {
                    ++cursor;
                    if (!followedPointer) position = cursor;
                    return name;
                }

                if ((labelLength & 0xC0) == 0xC0) {
                    if (cursor + 1 >= size || ++pointerCount > size) return std::nullopt;
                    const size_t pointer = (static_cast<size_t>(labelLength & 0x3F) << 8) | data[cursor + 1];
                    if (pointer >= size) return std::nullopt;
                    if (!followedPointer) position = cursor + 2;
                    cursor = pointer;
                    followedPointer = true;
                    continue;
                }

                if ((labelLength & 0xC0) != 0 || labelLength > 63 || cursor + 1 + labelLength > size) {
                    return std::nullopt;
                }

                if (!name.empty()) name += '.';
                name.append(reinterpret_cast<const char*>(data + cursor + 1), labelLength);
                cursor += 1 + labelLength;
            }

            return std::nullopt;
        }

        std::string addressToString(int family, const uint8_t* address) {
            char text[INET6_ADDRSTRLEN]{};
            return inet_ntop(family, address, text, sizeof(text)) ? text : "";
        }
    }

    std::optional<DNSResponse> DNSParser::parseResponse(const PacketData& rawData) {
        const uint8_t* buffer = rawData.payload.data();
        const size_t size = rawData.payload.size();
        if (size < 14) return std::nullopt;

        size_t offset = 14;
        uint16_t etherType = readU16(buffer + 12);
        while (etherType == vlanTag || etherType == providerVlanTag || etherType == doubleVlanTag) {
            if (size < offset + 4) return std::nullopt;
            etherType = readU16(buffer + offset + 2);
            offset += 4;
        }
        // Locate the UDP header end, regardless of IPv4 or IPv6 transport.
        size_t ipEnd = 0;
        if (etherType == ethernetIPv4) {
            if (size < offset + 20) return std::nullopt;
            const uint8_t versionAndHeaderLength = buffer[offset];
            const size_t ipHeaderLength = (versionAndHeaderLength & 0x0F) * 4;
            if ((versionAndHeaderLength >> 4) != 4 || ipHeaderLength < 20 || size < offset + ipHeaderLength) {
                return std::nullopt;
            }
            const uint16_t ipTotalLength = readU16(buffer + offset + 2);
            if (ipTotalLength < ipHeaderLength || buffer[offset + 9] != 17) return std::nullopt;
            ipEnd = std::min(size, offset + static_cast<size_t>(ipTotalLength));
            offset += ipHeaderLength;
        } else if (etherType == ethernetIPv6) {
            constexpr size_t v6FixedHeader = 40;
            if (size < offset + v6FixedHeader) return std::nullopt;
            const uint16_t payloadLen = readU16(buffer + offset + 4);
            ipEnd = std::min(size, offset + v6FixedHeader + static_cast<size_t>(payloadLen));
            uint8_t next = buffer[offset + 6];
            size_t pos = offset + v6FixedHeader;
            // Walk extension headers to find UDP.
            while (next != 17 && pos < ipEnd) {
                if (next == 0 || next == 43 || next == 60 || next == 135) {
                    if (ipEnd < pos + 2) return std::nullopt;
                    const uint8_t newNext = buffer[pos];
                    const size_t hdrLen = (static_cast<size_t>(buffer[pos + 1]) + 1) * 8;
                    if (ipEnd < pos + hdrLen) return std::nullopt;
                    pos += hdrLen;
                    next = newNext;
                } else if (next == 44) {
                    if (ipEnd < pos + 8) return std::nullopt;
                    next = buffer[pos];
                    pos += 8;
                } else {
                    return std::nullopt;
                }
            }
            if (next != 17) return std::nullopt;
            offset = pos;
        } else {
            return std::nullopt;
        }
        if (ipEnd < offset + 8) return std::nullopt;
        const uint16_t srcPort = readU16(buffer + offset);
        const uint16_t dstPort = readU16(buffer + offset + 2);
        const bool isDns  = srcPort == dnsPort  || dstPort == dnsPort;
        const bool isMdns = srcPort == mdnsPort || dstPort == mdnsPort;
        if (!isDns && !isMdns) return std::nullopt;

        const uint16_t udpLength = readU16(buffer + offset + 4);
        if (udpLength < 8) return std::nullopt;
        const size_t udpEnd = std::min(ipEnd, offset + static_cast<size_t>(udpLength));
        offset += 8;
        if (udpEnd < offset + 12) return std::nullopt;

        const uint8_t* dns = buffer + offset;
        const size_t dnsSize = udpEnd - offset;
        const uint16_t flags = readU16(dns + 2);
        if ((flags & 0x8000) == 0) return std::nullopt; // Queries do not populate the cache.

        const uint16_t questionCount = readU16(dns + 4);
        const uint16_t answerCount = readU16(dns + 6);
        size_t position = 12;
        DNSResponse response;

        for (uint16_t question = 0; question < questionCount; ++question) {
            const auto name = readName(dns, dnsSize, position);
            if (!name || dnsSize - position < 4) return std::nullopt;
            if (question == 0) response.queryName = *name;
            position += 4; // QTYPE + QCLASS
        }

        for (uint16_t answer = 0; answer < answerCount; ++answer) {
            const auto name = readName(dns, dnsSize, position);
            if (!name || dnsSize - position < 10) return std::nullopt;

            const uint16_t type = readU16(dns + position);
            const uint16_t recordClass = readU16(dns + position + 2);
            const uint32_t ttl = readU32(dns + position + 4);
            (void)ttl;
            const size_t dataLength = readU16(dns + position + 8);
            position += 10;
            if (dataLength > dnsSize - position) return std::nullopt;
            const size_t recordEnd = position + dataLength;

            if (recordClass == dnsClassInternet && type == 1 && dataLength == 4) {
                response.answers.push_back({DNSRecordType::A, *name, addressToString(AF_INET, dns + position)});
            } else if (recordClass == dnsClassInternet && type == 28 && dataLength == 16) {
                response.answers.push_back({DNSRecordType::AAAA, *name, addressToString(AF_INET6, dns + position)});
            } else if (recordClass == dnsClassInternet && type == 5) {
                size_t cnamePosition = position;
                const auto canonicalName = readName(dns, dnsSize, cnamePosition);
                if (canonicalName && cnamePosition <= recordEnd) {
                    response.answers.push_back({DNSRecordType::CNAME, *name, *canonicalName});
                }
            }

            position = recordEnd;
        }

        return response;
    }

} // namespace core
