#include "core/DNSParser.hpp"
#include "core/PacketData.hpp"
#include "core/ProtocolParser.hpp"

#include <cstddef>
#include <cstdint>

// libFuzzer entry point. Treats the input bytes as a captured-packet payload
// and feeds them through the stateless network parsers. Return values are
// ignored — the goal is to verify that arbitrary input cannot crash the
// parsers, trigger out-of-bounds reads, or hit undefined behavior. Sanitizers
// (ASan/UBSan, linked alongside libFuzzer) detect those conditions.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const uint32_t length = static_cast<uint32_t>(size);
    core::PacketData raw(static_cast<int64_t>(0), length, length, data);

    (void)core::ProtocolParser::parse(raw);
    (void)core::DNSParser::parseResponse(raw);
    return 0;
}
