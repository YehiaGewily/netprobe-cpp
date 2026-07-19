#include "core/FlowExporter.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

// The exported files are the project's machine-readable contract with other
// tools, so these tests pin both the shape of the output and — more
// importantly — its robustness to hostile field values. Hostnames and SNI
// arrive as raw bytes off the wire; a naive writer turns a malformed one into
// a document no consumer can parse.
namespace {

    core::Flow makeFlow(const std::string& hostname = "example.com") {
        core::Flow flow;
        flow.key.srcIP = "192.168.1.10";
        flow.key.srcPort = 50000;
        flow.key.dstIP = "93.184.216.34";
        flow.key.dstPort = 443;
        flow.key.protocol = "TCP";
        flow.hostname = hostname;
        flow.service = "HTTPS";
        flow.process = "firefox";
        flow.bytesUp = 1024;
        flow.bytesDown = 8192;
        flow.packets = 12;
        flow.firstSeen = 1'700'000'000'000'000;
        flow.lastSeen = 1'700'000'005'000'000;
        flow.rateBytesPerSecond = 1536.0;
        flow.initialRttMicroseconds = 24'500;
        flow.retransmissionsUp = 3;
        flow.outOfOrderDown = 2;
        return flow;
    }

    std::string toJson(const std::vector<core::Flow>& flows) {
        std::ostringstream out;
        core::FlowExporter::writeJson(flows, out);
        return out.str();
    }

    std::string toCsv(const std::vector<core::Flow>& flows) {
        std::ostringstream out;
        core::FlowExporter::writeCsv(flows, out);
        return out.str();
    }

    std::string jsonStringOf(const std::string& value) {
        std::string encoded;
        core::FlowExporter::appendJsonString(encoded, value);
        return encoded;
    }

    // Structural check that every brace/bracket is balanced and every quote
    // is closed, honouring escapes. Enough to catch a field value that has
    // broken out of its string, which is the failure mode that matters.
    bool jsonIsStructurallyBalanced(const std::string& document) {
        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (const char c : document) {
            if (inString) {
                if (escaped)            escaped = false;
                else if (c == '\\')     escaped = true;
                else if (c == '"')      inString = false;
                else if (static_cast<unsigned char>(c) < 0x20) return false;
                continue;
            }
            if (c == '"')                    inString = true;
            else if (c == '{' || c == '[')   ++depth;
            else if (c == '}' || c == ']') {
                --depth;
                if (depth < 0) return false;
            }
        }
        return depth == 0 && !inString;
    }

} // namespace

TEST(FlowExporterTest, JsonContainsExpectedFieldsAndValues) {
    const auto document = toJson({makeFlow()});

    EXPECT_TRUE(jsonIsStructurallyBalanced(document)) << document;
    EXPECT_NE(document.find("\"flow_count\": 1"), std::string::npos);
    EXPECT_NE(document.find("\"src_ip\": \"192.168.1.10\""), std::string::npos);
    EXPECT_NE(document.find("\"dst_port\": 443"), std::string::npos);
    EXPECT_NE(document.find("\"protocol\": \"TCP\""), std::string::npos);
    EXPECT_NE(document.find("\"hostname\": \"example.com\""), std::string::npos);
    EXPECT_NE(document.find("\"bytes_down\": 8192"), std::string::npos);
    EXPECT_NE(document.find("\"packets\": 12"), std::string::npos);
    EXPECT_NE(document.find("\"initial_rtt_us\": 24500"), std::string::npos);
    EXPECT_NE(document.find("\"duration_sec\": 5"), std::string::npos);
    EXPECT_NE(document.find("\"encrypted_tunnel\": false"), std::string::npos);
    EXPECT_NE(document.find("\"retransmissions_up\": 3"), std::string::npos);
    EXPECT_NE(document.find("\"retransmissions_down\": 0"), std::string::npos);
    EXPECT_NE(document.find("\"out_of_order_down\": 2"), std::string::npos);
}

TEST(FlowExporterTest, JsonWithNoFlowsIsStillValid) {
    const auto document = toJson({});

    EXPECT_TRUE(jsonIsStructurallyBalanced(document)) << document;
    EXPECT_NE(document.find("\"flow_count\": 0"), std::string::npos);
    EXPECT_NE(document.find("\"flows\": []"), std::string::npos);
}

TEST(FlowExporterTest, JsonEscapesQuotesBackslashesAndControlCharacters) {
    EXPECT_EQ(jsonStringOf("say \"hi\""), "\"say \\\"hi\\\"\"");
    EXPECT_EQ(jsonStringOf("back\\slash"), "\"back\\\\slash\"");
    EXPECT_EQ(jsonStringOf("line\nbreak"), "\"line\\nbreak\"");
    EXPECT_EQ(jsonStringOf("tab\there"), "\"tab\\there\"");
    EXPECT_EQ(jsonStringOf(std::string("nul\0byte", 8)), "\"nul\\u0000byte\"");
    EXPECT_EQ(jsonStringOf("bell\x07"), "\"bell\\u0007\"");
}

TEST(FlowExporterTest, JsonPreservesValidMultiByteUtf8) {
    // U+00E9 (2-byte), U+4E2D (3-byte), U+1F600 (4-byte) must survive intact.
    EXPECT_EQ(jsonStringOf("caf\xC3\xA9"), "\"caf\xC3\xA9\"");
    EXPECT_EQ(jsonStringOf("\xE4\xB8\xAD"), "\"\xE4\xB8\xAD\"");
    EXPECT_EQ(jsonStringOf("\xF0\x9F\x98\x80"), "\"\xF0\x9F\x98\x80\"");
}

TEST(FlowExporterTest, JsonReplacesMalformedUtf8RatherThanEmittingIt) {
    // Each of these is a hostname an attacker could put in an SNI field.
    const std::vector<std::string> malformed = {
        "\xFF\xFE",                 // never-valid lead bytes
        "\xC3",                     // truncated 2-byte sequence
        "\xE4\xB8",                 // truncated 3-byte sequence
        "\xC0\xAF",                 // overlong encoding of '/'
        "\xED\xA0\x80",             // UTF-16 surrogate half
        "\xF5\x80\x80\x80",         // beyond U+10FFFF
        "host\x80name",             // stray continuation byte
    };

    for (const auto& value : malformed) {
        const auto encoded = jsonStringOf(value);
        EXPECT_TRUE(jsonIsStructurallyBalanced(encoded))
            << "malformed input produced unbalanced JSON: " << encoded;
        // U+FFFD, not the raw bytes.
        EXPECT_NE(encoded.find("\xEF\xBF\xBD"), std::string::npos)
            << "expected a replacement character for: " << encoded;
    }

    auto flow = makeFlow("\xFF\xFE evil.example.com");
    EXPECT_TRUE(jsonIsStructurallyBalanced(toJson({flow})));
}

TEST(FlowExporterTest, CsvKeepsItsHeaderAndQuotesEmbeddedCommas) {
    const auto csv = toCsv({makeFlow("a,b\"c")});

    ASSERT_FALSE(csv.empty());
    const auto headerEnd = csv.find('\n');
    ASSERT_NE(headerEnd, std::string::npos);
    EXPECT_EQ(csv.substr(0, headerEnd),
        "host,src_ip,src_port,dst_ip,dst_port,protocol,service,process,country,organization,"
        "packets,bytes_up,bytes_down,rate_bytes_per_sec,initial_rtt_ms,duration_sec,"
        "retransmissions_up,retransmissions_down,out_of_order_up,out_of_order_down");
    // The comma and quote must be escaped, not passed through raw.
    EXPECT_NE(csv.find("\"a,b\"\"c\""), std::string::npos) << csv;
}
