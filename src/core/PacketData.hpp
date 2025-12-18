#pragma once

#include <vector>
#include <cstdint>
#include <chrono>

namespace core {

    struct PacketData {
        int64_t timestamp;  // Microseconds since epoch
        uint32_t length;
        std::vector<uint8_t> payload;

        PacketData() = default;
        PacketData(int64_t ts, uint32_t len, const uint8_t* data)
            : timestamp(ts), length(len), payload(data, data + len) {}
    };

} // namespace core
