#pragma once

#include <cstdint>

namespace core {

#pragma pack(push, 1)

    struct EthernetHeader {
        uint8_t dest[6];
        uint8_t src[6];
        uint16_t type; // EthType
    };

    struct IPv4Header {
        uint8_t versionHlen; // Version (4 bits) + IHL (4 bits)
        uint8_t tos;
        uint16_t totalLength;
        uint16_t id;
        uint16_t flagsFragOffset;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t srcAddr;
        uint32_t dstAddr;
    };

    struct TCPHeader {
        uint16_t srcPort;
        uint16_t dstPort;
        uint32_t seq;
        uint32_t ack;
        uint8_t dataOffsetReserved; // Data Offset (4 bits) + Reserved (3 bits) + NS (1 bit)
        uint8_t flags;
        uint16_t windowSize;
        uint16_t checksum;
        uint16_t urgentPointer;
    };

    struct UDPHeader {
        uint16_t srcPort;
        uint16_t dstPort;
        uint16_t length;
        uint16_t checksum;
    };

#pragma pack(pop)

} // namespace core
