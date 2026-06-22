#pragma once

#include <vector>
#include <cstdint>
#include <chrono>

namespace core {

    struct PacketData {
        int64_t timestamp;  // Microseconds since epoch
        uint32_t length;    // Original on-the-wire length reported by Npcap
        uint32_t capturedLength;
        std::vector<uint8_t> payload;

        PacketData() = default;
        PacketData(int64_t ts, uint32_t wireLength, uint32_t capLength, const uint8_t* data)
            : timestamp(ts), length(wireLength), capturedLength(capLength)
        {
            if (data && capturedLength > 0) {
                payload.assign(data, data + capturedLength);
            }
        }
    };

} // namespace core
