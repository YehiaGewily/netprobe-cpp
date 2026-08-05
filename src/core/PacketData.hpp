#pragma once

#include "core/LinkType.hpp"

#include <vector>
#include <cstdint>
#include <chrono>

namespace core {

    struct PacketData {
        int64_t timestamp;  // Microseconds since epoch
        uint32_t length;    // Original on-the-wire length reported by Npcap
        uint32_t capturedLength;
        // Link-layer encapsulation of `payload`. Defaults to Ethernet because
        // that is what every synthetic fixture and the overwhelming majority of
        // real adapters use; live/offline captures overwrite it from
        // pcap_datalink() so loopback and cooked captures decode correctly.
        LinkType linkType = LinkType::Ethernet;
        std::vector<uint8_t> payload;

        PacketData() = default;
        PacketData(int64_t ts, uint32_t wireLength, uint32_t capLength, const uint8_t* data,
            LinkType link = LinkType::Ethernet)
            : timestamp(ts), length(wireLength), capturedLength(capLength), linkType(link)
        {
            if (data && capturedLength > 0) {
                payload.assign(data, data + capturedLength);
            }
        }
    };

} // namespace core
