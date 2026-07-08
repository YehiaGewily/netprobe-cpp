#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace core {

    struct ParsedPacket {
        int64_t timestamp = 0;
        std::string srcIP;
        std::string dstIP;
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;
        std::string protocol; // "TCP", "UDP", "ICMP", "ARP", "GRE", ...
        uint32_t length = 0;

        // TCP flag bits — populated only when protocol == "TCP". Used by
        // FlowAggregator to identify the SYN / SYN-ACK pair for initial-RTT.
        bool tcpSyn = false;
        bool tcpAck = false;
        bool tcpFin = false;
        bool tcpRst = false;
        // Sequence number of the first payload byte, so TlsReassembler can order
        // segments without re-parsing the header.
        uint32_t tcpSeq = 0;

        // Where the layer-4 payload lives inside PacketData::payload, so
        // downstream stages (TLS/QUIC reassembly, follow-stream) can find the
        // bytes without re-walking the headers. payloadLength == 0 means the
        // packet carried no L4 payload (or we could not locate it).
        size_t payloadOffset = 0;
        size_t payloadLength = 0;

        // Tunnel encapsulation, outermost first, e.g. "GRE" or "IPv4/GRE".
        // Empty for ordinary traffic. When set, srcIP/dstIP describe the
        // innermost (real) endpoints and outerSrcIP/outerDstIP the carrier.
        std::string tunnel;
        std::string outerSrcIP;
        std::string outerDstIP;
        // True when the payload is encrypted by the tunnel itself (ESP,
        // WireGuard, OpenVPN), so no inner endpoints can ever be recovered.
        bool encryptedTunnel = false;

        // DPI Fields
        std::string sni;      // Server Name Indication (TLS or QUIC ClientHello)
        std::string service;  // "Discord", "Spotify", "YouTube", or empty
        std::string hostname; // Host: header from cleartext HTTP, if any
        std::string info;     // Human-readable summary, e.g. "GET /index.html"

        std::string payloadSummary; // Hex dump or text preview
    };

} // namespace core
