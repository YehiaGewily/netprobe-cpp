#include "core/DNSParser.hpp"
#include "core/NetworkPlatform.hpp"
#include "core/ProtocolParser.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>

namespace core {
    namespace {
        constexpr uint16_t dnsPort = 53;
        constexpr uint16_t mdnsPort = 5353;
        constexpr uint16_t llmnrPort = 5355;
        constexpr uint16_t dnsClassInternet = 1;

        // RR type codes.
        constexpr uint16_t rrA     = 1;
        constexpr uint16_t rrCname = 5;
        constexpr uint16_t rrPtr   = 12;
        constexpr uint16_t rrTxt   = 16;
        constexpr uint16_t rrAaaa  = 28;
        constexpr uint16_t rrSrv   = 33;
        constexpr uint16_t rrSvcb  = 64;
        constexpr uint16_t rrHttps = 65;

        // SVCB parameter keys (RFC 9460 §14.3.2).
        constexpr uint16_t svcParamEch = 5;

        constexpr size_t kMaxTxtBytes = 255;

        uint16_t readU16(const uint8_t* bytes) {
            return static_cast<uint16_t>(bytes[0]) << 8 | bytes[1];
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

        std::vector<std::string> splitLabels(const std::string& name) {
            std::vector<std::string> labels;
            size_t start = 0;
            while (start <= name.size()) {
                const size_t dot = name.find('.', start);
                if (dot == std::string::npos) {
                    labels.push_back(name.substr(start));
                    break;
                }
                labels.push_back(name.substr(start, dot - start));
                start = dot + 1;
            }
            return labels;
        }

        std::string toLower(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        }

        // Walk a SVCB/HTTPS RDATA blob, reporting whether it advertises ECH.
        // Layout: priority(2), TargetName, then zero or more {key(2), len(2), value}.
        bool svcbAdvertisesEch(const uint8_t* message, size_t size, size_t position, size_t recordEnd) {
            if (recordEnd - position < 2) return false;
            position += 2; // priority

            size_t targetPosition = position;
            if (!readName(message, size, targetPosition)) return false;
            position = targetPosition;

            while (position + 4 <= recordEnd) {
                const uint16_t key = readU16(message + position);
                const uint16_t valueLength = readU16(message + position + 2);
                position += 4;
                if (valueLength > recordEnd - position) return false;
                if (key == svcParamEch && valueLength > 0) return true;
                position += valueLength;
            }
            return false;
        }

        // "1.1.168.192.in-addr.arpa" -> "192.168.1.1"
        std::optional<std::string> reverseIpv4(const std::vector<std::string>& labels) {
            if (labels.size() != 6) return std::nullopt;
            std::string address;
            for (int i = 3; i >= 0; --i) {
                const std::string& octet = labels[static_cast<size_t>(i)];
                if (octet.empty() || octet.size() > 3) return std::nullopt;
                for (char c : octet) {
                    if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
                }
                if (std::stoi(octet) > 255) return std::nullopt;
                if (!address.empty()) address += '.';
                address += octet;
            }
            return address;
        }

        // 32 reversed nibble labels + "ip6.arpa" -> a canonical IPv6 string.
        std::optional<std::string> reverseIpv6(const std::vector<std::string>& labels) {
            if (labels.size() != 34) return std::nullopt;
            uint8_t bytes[16]{};
            for (size_t i = 0; i < 32; ++i) {
                const std::string& nibble = labels[31 - i];
                if (nibble.size() != 1 || !std::isxdigit(static_cast<unsigned char>(nibble[0]))) {
                    return std::nullopt;
                }
                const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(nibble[0])));
                const uint8_t value = static_cast<uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10);
                if (i % 2 == 0) bytes[i / 2] = static_cast<uint8_t>(value << 4);
                else            bytes[i / 2] = static_cast<uint8_t>(bytes[i / 2] | value);
            }
            std::string text = addressToString(AF_INET6, bytes);
            if (text.empty()) return std::nullopt;
            return text;
        }
    }

    std::optional<std::string> DNSParser::reverseNameToAddress(const std::string& name) {
        const auto labels = splitLabels(toLower(name));
        if (labels.size() >= 3) {
            const std::string& tld = labels[labels.size() - 1];
            const std::string& sld = labels[labels.size() - 2];
            if (tld == "arpa" && sld == "in-addr") return reverseIpv4(labels);
            if (tld == "arpa" && sld == "ip6")     return reverseIpv6(labels);
        }
        return std::nullopt;
    }

    std::optional<DNSResponse> DNSParser::parseMessage(const uint8_t* message, size_t size) {
        if (!message || size < 12) return std::nullopt;

        const uint16_t flags = readU16(message + 2);
        if ((flags & 0x8000) == 0) return std::nullopt; // Queries do not populate the cache.

        const uint16_t questionCount = readU16(message + 4);
        const uint16_t answerCount = readU16(message + 6);
        size_t position = 12;
        DNSResponse response;

        for (uint16_t question = 0; question < questionCount; ++question) {
            const auto name = readName(message, size, position);
            if (!name || size - position < 4) return std::nullopt;
            if (question == 0) response.queryName = *name;
            position += 4; // QTYPE + QCLASS
        }

        for (uint16_t answer = 0; answer < answerCount; ++answer) {
            const auto name = readName(message, size, position);
            if (!name || size - position < 10) return std::nullopt;
            // Bound once, immediately after the guard, rather than
            // dereferencing the optional at each of the record types below.
            // Clearer, and it keeps clang-tidy's optional-access analysis from
            // losing track of the guard across the TXT chunk loop.
            const std::string& owner = *name;

            const uint16_t type = readU16(message + position);
            // mDNS reuses the top class bit as a cache-flush flag, so compare
            // only the low 15 bits.
            const uint16_t recordClass = readU16(message + position + 2) & 0x7FFF;
            const size_t dataLength = readU16(message + position + 8);
            position += 10;
            if (dataLength > size - position) return std::nullopt;
            const size_t recordEnd = position + dataLength;

            if (recordClass == dnsClassInternet) {
                switch (type) {
                case rrA:
                    if (dataLength == 4) {
                        response.answers.push_back({DNSRecordType::A, owner,
                            addressToString(AF_INET, message + position), 0});
                    }
                    break;
                case rrAaaa:
                    if (dataLength == 16) {
                        response.answers.push_back({DNSRecordType::AAAA, owner,
                            addressToString(AF_INET6, message + position), 0});
                    }
                    break;
                case rrCname: {
                    size_t cursor = position;
                    const auto canonicalName = readName(message, size, cursor);
                    if (canonicalName && cursor <= recordEnd) {
                        response.answers.push_back({DNSRecordType::CNAME, owner, *canonicalName, 0});
                    }
                    break;
                }
                case rrPtr: {
                    size_t cursor = position;
                    const auto target = readName(message, size, cursor);
                    if (target && cursor <= recordEnd && !target->empty()) {
                        response.answers.push_back({DNSRecordType::PTR, owner, *target, 0});
                    }
                    break;
                }
                case rrSrv: {
                    if (dataLength < 7) break;
                    const uint16_t priority = readU16(message + position);
                    const uint16_t port = readU16(message + position + 4);
                    size_t cursor = position + 6;
                    const auto target = readName(message, size, cursor);
                    if (target && cursor <= recordEnd && !target->empty()) {
                        response.answers.push_back({DNSRecordType::SRV, owner,
                            *target + ":" + std::to_string(port), priority});
                    }
                    break;
                }
                case rrTxt: {
                    // Character-strings, each length-prefixed. Join with spaces.
                    std::string text;
                    size_t cursor = position;
                    while (cursor < recordEnd && text.size() < kMaxTxtBytes) {
                        const size_t chunkLength = message[cursor++];
                        if (chunkLength > recordEnd - cursor) break;
                        if (!text.empty()) text += ' ';
                        text.append(reinterpret_cast<const char*>(message + cursor),
                            std::min(chunkLength, kMaxTxtBytes - text.size()));
                        cursor += chunkLength;
                    }
                    if (!text.empty()) {
                        response.answers.push_back({DNSRecordType::TXT, owner, text, 0});
                    }
                    break;
                }
                case rrSvcb:
                case rrHttps: {
                    if (dataLength < 2) break;
                    const uint16_t priority = readU16(message + position);
                    size_t cursor = position + 2;
                    const auto target = readName(message, size, cursor);
                    const bool ech = svcbAdvertisesEch(message, size, position, recordEnd);
                    if (ech) response.encryptedClientHelloAdvertised = true;
                    response.answers.push_back({
                        type == rrHttps ? DNSRecordType::HTTPS : DNSRecordType::SVCB,
                        owner,
                        target && !target->empty() ? *target : owner,
                        priority});
                    break;
                }
                default:
                    break;
                }
            }

            position = recordEnd;
        }

        return response;
    }

    std::optional<DNSResponse> DNSParser::parseResponse(const PacketData& rawData,
        const ParsedPacket& parsed) {

        if (parsed.protocol != "UDP" || parsed.payloadLength == 0) return std::nullopt;

        const bool isDns = parsed.srcPort == dnsPort || parsed.dstPort == dnsPort
            || parsed.srcPort == mdnsPort || parsed.dstPort == mdnsPort
            || parsed.srcPort == llmnrPort || parsed.dstPort == llmnrPort;
        if (!isDns) return std::nullopt;

        if (parsed.payloadOffset >= rawData.payload.size()) return std::nullopt;
        const size_t available = std::min(parsed.payloadLength,
            rawData.payload.size() - parsed.payloadOffset);
        return parseMessage(rawData.payload.data() + parsed.payloadOffset, available);
    }

    std::optional<DNSResponse> DNSParser::parseResponse(const PacketData& rawData) {
        // Locating the UDP payload means walking the link, network, and tunnel
        // layers — exactly what ProtocolParser already does, including for
        // loopback and cooked captures.
        return parseResponse(rawData, ProtocolParser::parse(rawData));
    }

} // namespace core
