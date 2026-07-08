#pragma once

#include "core/PacketData.hpp"
#include "core/ParsedPacket.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace core {

    enum class DNSRecordType {
        A,
        AAAA,
        CNAME,
        PTR,   // Reverse lookup — names LAN devices that never appear in an A record
        SRV,
        TXT,
        HTTPS, // RR type 65 (RFC 9460) — carries HTTP/3 hints and ECH configs
        SVCB,  // RR type 64
    };

    struct DNSRecord {
        DNSRecordType type;
        std::string name;
        std::string value;
        uint16_t priority = 0; // SRV / SVCB / HTTPS priority field
    };

    struct DNSResponse {
        std::string queryName;
        std::vector<DNSRecord> answers;
        // True when an HTTPS/SVCB answer advertised an "ech" parameter. Clients
        // that honour it will encrypt the SNI of the connection that follows, so
        // SNI-based service identification is about to stop working for it.
        bool encryptedClientHelloAdvertised = false;
    };

    class DNSParser {
    public:
        // Parses a DNS or mDNS response carried over UDP (IPv4 or IPv6, any
        // supported link type). Returns no value when the packet is not a DNS
        // response we can read.
        static std::optional<DNSResponse> parseResponse(const PacketData& rawData);

        // Overload for callers that have already parsed the packet, avoiding a
        // second walk of the headers.
        static std::optional<DNSResponse> parseResponse(const PacketData& rawData,
            const ParsedPacket& parsed);

        // Parses a bare DNS message (no transport headers).
        static std::optional<DNSResponse> parseMessage(const uint8_t* message, size_t size);

        // Converts an in-addr.arpa / ip6.arpa PTR owner name back into the IP
        // address it describes, so a reverse answer can populate the hostname
        // cache. Returns no value when `name` is not a reverse-lookup name.
        static std::optional<std::string> reverseNameToAddress(const std::string& name);
    };

} // namespace core
