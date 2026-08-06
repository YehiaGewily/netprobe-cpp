#include "core/FlowExporter.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <format>
#include <fstream>
#include <ostream>

#ifndef NETPROBE_VERSION
#define NETPROBE_VERSION "unknown"
#endif

namespace core {

    namespace {

        std::string formatFloat(double value, int precision) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.*f", precision, value);
            return std::string(buf);
        }

        std::string csvEscape(const std::string& value) {
            if (value.find_first_of(",\"\n") == std::string::npos) return value;
            std::string escaped = "\"";
            for (char c : value) {
                if (c == '"') escaped += "\"\"";
                else escaped += c;
            }
            escaped += '"';
            return escaped;
        }

        GeoIPInfo lookupGeo(GeoIPResolver* geo, const std::string& ip) {
            return geo ? geo->lookup(ip) : GeoIPInfo{};
        }

        double rttMillisecondsOf(const Flow& flow) {
            return flow.initialRttMicroseconds > 0
                ? static_cast<double>(flow.initialRttMicroseconds) / 1000.0
                : 0.0;
        }

        int64_t durationSecondsOf(const Flow& flow) {
            return std::max<int64_t>(0, (flow.lastSeen - flow.firstSeen) / 1'000'000);
        }

        int64_t currentUnixTimeMicroseconds() {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }

    } // namespace

    void FlowExporter::appendJsonString(std::string& out, const std::string& value) {
        static constexpr char kHex[] = "0123456789abcdef";

        out += '"';
        const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
        const size_t size = value.size();

        for (size_t i = 0; i < size;) {
            const unsigned char c = bytes[i];

            if (c < 0x80) {
                switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        out += "\\u00";
                        out += kHex[(c >> 4) & 0x0F];
                        out += kHex[c & 0x0F];
                    } else {
                        out += static_cast<char>(c);
                    }
                    break;
                }
                ++i;
                continue;
            }

            // Multi-byte sequence: decode it so malformed input can be caught
            // rather than copied through into an unparseable document.
            size_t length = 0;
            uint32_t codepoint = 0;
            if ((c & 0xE0) == 0xC0)      { length = 2; codepoint = c & 0x1FU; }
            else if ((c & 0xF0) == 0xE0) { length = 3; codepoint = c & 0x0FU; }
            else if ((c & 0xF8) == 0xF0) { length = 4; codepoint = c & 0x07U; }

            bool valid = length != 0 && i + length <= size;
            if (valid) {
                for (size_t k = 1; k < length; ++k) {
                    const unsigned char continuation = bytes[i + k];
                    if ((continuation & 0xC0) != 0x80) { valid = false; break; }
                    codepoint = (codepoint << 6) | (continuation & 0x3FU);
                }
            }
            // Reject overlong encodings, UTF-16 surrogate halves, and
            // anything past the Unicode range — all of which are ill-formed
            // even though their lead bytes look plausible.
            if (valid) {
                const bool overlong = (length == 2 && codepoint < 0x80)
                    || (length == 3 && codepoint < 0x800)
                    || (length == 4 && codepoint < 0x10000);
                const bool surrogate = codepoint >= 0xD800 && codepoint <= 0xDFFF;
                if (overlong || surrogate || codepoint > 0x10FFFF) valid = false;
            }

            if (!valid) {
                out += "\xEF\xBF\xBD"; // U+FFFD REPLACEMENT CHARACTER
                ++i;                   // resynchronize one byte at a time
                continue;
            }

            out.append(reinterpret_cast<const char*>(bytes + i), length);
            i += length;
        }

        out += '"';
    }

    void FlowExporter::writeCsv(const std::vector<Flow>& flows, std::ostream& out,
        GeoIPResolver* geo) {
        // New columns are appended rather than inserted so existing consumers
        // that index by position keep working.
        out << "host,src_ip,src_port,dst_ip,dst_port,protocol,service,process,country,organization,"
               "packets,bytes_up,bytes_down,rate_bytes_per_sec,initial_rtt_ms,duration_sec,"
               "retransmissions_up,retransmissions_down,out_of_order_up,out_of_order_down\n";
        for (const auto& flow : flows) {
            const auto info = lookupGeo(geo, flow.key.dstIP);
            const std::string& host = flow.hostname.empty() ? flow.key.dstIP : flow.hostname;
            out << csvEscape(host) << ','
                << flow.key.srcIP << ','
                << flow.key.srcPort << ','
                << flow.key.dstIP << ','
                << flow.key.dstPort << ','
                << flow.key.protocol << ','
                << csvEscape(flow.service) << ','
                << csvEscape(flow.process) << ','
                << csvEscape(info.country) << ','
                << csvEscape(organizationLabel(info)) << ','
                << flow.packets << ','
                << flow.bytesUp << ','
                << flow.bytesDown << ','
                << formatFloat(flow.rateBytesPerSecond, 1) << ','
                << formatFloat(rttMillisecondsOf(flow), 2) << ','
                << durationSecondsOf(flow) << ','
                << flow.retransmissionsUp << ','
                << flow.retransmissionsDown << ','
                << flow.outOfOrderUp << ','
                << flow.outOfOrderDown << '\n';
        }
    }

    void FlowExporter::writeJson(const std::vector<Flow>& flows, std::ostream& out,
        GeoIPResolver* geo) {
        std::string document;
        document.reserve(flows.size() * 320 + 128);

        document += "{\n  \"netprobe_version\": ";
        appendJsonString(document, NETPROBE_VERSION);
        document += ",\n  \"generated_unix_us\": ";
        document += std::format("{}", currentUnixTimeMicroseconds());
        document += ",\n  \"flow_count\": ";
        document += std::format("{}", flows.size());
        document += ",\n  \"flows\": [";

        bool first = true;
        for (const auto& flow : flows) {
            const auto info = lookupGeo(geo, flow.key.dstIP);
            document += first ? "\n    {" : ",\n    {";
            first = false;

            document += "\n      \"src_ip\": ";
            appendJsonString(document, flow.key.srcIP);
            document += ",\n      \"src_port\": ";
            document += std::format("{}", flow.key.srcPort);
            document += ",\n      \"dst_ip\": ";
            appendJsonString(document, flow.key.dstIP);
            document += ",\n      \"dst_port\": ";
            document += std::format("{}", flow.key.dstPort);
            document += ",\n      \"protocol\": ";
            appendJsonString(document, flow.key.protocol);
            document += ",\n      \"service\": ";
            appendJsonString(document, flow.service);
            document += ",\n      \"hostname\": ";
            appendJsonString(document, flow.hostname);
            document += ",\n      \"process\": ";
            appendJsonString(document, flow.process);
            document += ",\n      \"country\": ";
            appendJsonString(document, info.country);
            document += ",\n      \"asn\": ";
            document += std::format("{}", info.asn);
            document += ",\n      \"organization\": ";
            appendJsonString(document, info.organization);
            document += ",\n      \"packets\": ";
            document += std::format("{}", flow.packets);
            document += ",\n      \"bytes_up\": ";
            document += std::format("{}", flow.bytesUp);
            document += ",\n      \"bytes_down\": ";
            document += std::format("{}", flow.bytesDown);
            document += ",\n      \"first_seen_us\": ";
            document += std::format("{}", flow.firstSeen);
            document += ",\n      \"last_seen_us\": ";
            document += std::format("{}", flow.lastSeen);
            document += ",\n      \"duration_sec\": ";
            document += std::format("{}", durationSecondsOf(flow));
            document += ",\n      \"rate_bytes_per_sec\": ";
            document += formatFloat(flow.rateBytesPerSecond, 1);
            // Microseconds, as an integer: the JSON is for machines, and the
            // raw measurement avoids handing consumers a rounded float to
            // convert back. The CSV keeps milliseconds for spreadsheets.
            document += ",\n      \"initial_rtt_us\": ";
            document += std::format("{}", flow.initialRttMicroseconds);
            document += ",\n      \"retransmissions_up\": ";
            document += std::format("{}", flow.retransmissionsUp);
            document += ",\n      \"retransmissions_down\": ";
            document += std::format("{}", flow.retransmissionsDown);
            document += ",\n      \"out_of_order_up\": ";
            document += std::format("{}", flow.outOfOrderUp);
            document += ",\n      \"out_of_order_down\": ";
            document += std::format("{}", flow.outOfOrderDown);
            document += ",\n      \"encrypted_tunnel\": ";
            document += flow.encryptedTunnel ? "true" : "false";
            document += "\n    }";
        }

        document += flows.empty() ? "]\n}\n" : "\n  ]\n}\n";
        out << document;
    }

    bool FlowExporter::writeCsv(const std::vector<Flow>& flows, const std::string& path,
        std::string& error, GeoIPResolver* geo) {
        std::ofstream file(path, std::ios::trunc);
        if (!file) {
            error = "Unable to open the destination file for writing.";
            return false;
        }
        writeCsv(flows, file, geo);
        if (!file.good()) {
            error = "Writing the CSV file failed.";
            return false;
        }
        return true;
    }

    bool FlowExporter::writeJson(const std::vector<Flow>& flows, const std::string& path,
        std::string& error, GeoIPResolver* geo) {
        std::ofstream file(path, std::ios::trunc | std::ios::binary);
        if (!file) {
            error = "Unable to open the destination file for writing.";
            return false;
        }
        writeJson(flows, file, geo);
        if (!file.good()) {
            error = "Writing the JSON file failed.";
            return false;
        }
        return true;
    }

} // namespace core
