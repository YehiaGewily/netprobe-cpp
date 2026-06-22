#pragma once

#include "core/PacketData.hpp"

#include <optional>
#include <string>
#include <vector>

namespace core {

    enum class DNSRecordType {
        A,
        AAAA,
        CNAME,
    };

    struct DNSRecord {
        DNSRecordType type;
        std::string name;
        std::string value;
    };

    struct DNSResponse {
        std::string queryName;
        std::vector<DNSRecord> answers;
    };

    class DNSParser {
    public:
        // Parses an IPv4 UDP/53 DNS response and returns its supported answer records.
        static std::optional<DNSResponse> parseResponse(const PacketData& rawData);
    };

} // namespace core
