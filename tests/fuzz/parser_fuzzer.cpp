#include "core/DNSParser.hpp"
#include "core/LinkType.hpp"
#include "core/PacketData.hpp"
#include "core/ProtocolParser.hpp"
#include "core/QuicTracker.hpp"
#include "core/TlsReassembler.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>

// libFuzzer entry point. Treats the input bytes as a captured-packet payload
// and feeds them through the network parsers. Return values are ignored — the
// goal is to verify that arbitrary input cannot crash the parsers, trigger
// out-of-bounds reads, or hit undefined behavior. Sanitizers (ASan/UBSan,
// linked alongside libFuzzer) detect those conditions.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    // The first byte selects the link-layer encapsulation, so the fuzzer
    // exercises the cooked, loopback, and raw-IP header paths rather than only
    // Ethernet. The remaining bytes are the frame.
    constexpr core::LinkType linkTypes[] = {
        core::LinkType::Ethernet,
        core::LinkType::LinuxSLL,
        core::LinkType::LinuxSLL2,
        core::LinkType::NullLoopback,
        core::LinkType::Loop,
        core::LinkType::RawIP,
        core::LinkType::IPv4,
        core::LinkType::IPv6,
        core::LinkType::Unsupported,
    };
    const core::LinkType link = linkTypes[data[0] % std::size(linkTypes)];
    const uint8_t* frame = data + 1;
    const uint32_t length = static_cast<uint32_t>(size - 1);

    core::PacketData raw(static_cast<int64_t>(0), length, length, frame, link);

    const auto parsed = core::ProtocolParser::parse(raw);
    (void)core::DNSParser::parseResponse(raw, parsed);

    // The reassemblers hold state across calls and do their own bounds and
    // capacity arithmetic, so drive them with whatever payload the parse found.
    // Kept function-local-static so a single fuzz run accumulates state the way
    // a long capture would, exercising the eviction and expiry paths.
    static core::TlsReassembler tlsReassembler;
    static core::QuicTracker quicTracker;

    if (parsed.payloadLength > 0 && parsed.payloadOffset < raw.payload.size()) {
        const uint8_t* payload = raw.payload.data() + parsed.payloadOffset;
        const size_t payloadLength = std::min(parsed.payloadLength,
            raw.payload.size() - parsed.payloadOffset);

        if (parsed.protocol == "TCP") {
            (void)tlsReassembler.feed(parsed, payload, payloadLength);
        } else if (parsed.protocol == "UDP") {
            (void)quicTracker.feed(payload, payloadLength, parsed.timestamp);
        }
    }
    return 0;
}
