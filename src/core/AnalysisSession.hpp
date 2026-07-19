#pragma once

#include "core/FlowAggregator.hpp"
#include "core/HostnameCache.hpp"
#include "core/PacketData.hpp"
#include "core/ParsedPacket.hpp"
#include "core/ProcessResolver.hpp"
#include "core/QuicTracker.hpp"
#include "core/TlsReassembler.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace core {

    // Owns the per-packet analysis pipeline end to end: protocol decode,
    // cross-packet SNI recovery (TLS segment reassembly and QUIC Initial
    // decryption), DNS answer harvesting, hostname attribution, owning-process
    // lookup, and flow aggregation.
    //
    // This deliberately holds no presentation state. The GUI and the headless
    // CLI drive the same session and differ only in what they do with the
    // results, which is what keeps the two from drifting apart.
    class AnalysisSession {
    public:
        // What one packet turned into. `parsed` carries any SNI recovered from
        // earlier packets in the same stream, so it can differ from what a
        // stateless parse of these bytes alone would yield.
        struct Result {
            ParsedPacket parsed;
            // Best hostname known for the peer at ingest time: SNI, then an
            // HTTP Host header, then a DNS-derived name for either endpoint.
            std::string hostname;
            // Owning local process, resolved while the socket is still likely
            // to be in the OS table. Empty when disabled or unresolvable.
            std::string process;
        };

        // resolveProcesses: the OS socket-table walk is worthwhile for an
        // interactive session but pure overhead when replaying a capture file,
        // where the sockets are long gone.
        explicit AnalysisSession(bool resolveProcesses = true);

        Result feed(const PacketData& packet);

        std::vector<Flow> flows(int64_t nowMicroseconds) const;

        // Resets all analysis state: flows, hostnames, half-built handshakes,
        // and the encrypted-DNS counters.
        void clear();

        // Encrypted-DNS visibility. When resolution moves to DoH/DoT/DoQ the
        // hostname cache stops filling, and a consumer should say so rather
        // than silently showing bare addresses.
        uint64_t plaintextDnsResponses() const { return m_plaintextDnsResponses; }
        uint64_t encryptedDnsPackets() const { return m_encryptedDnsPackets; }
        bool echAdvertised() const { return m_echAdvertised; }

        // Display-time lookup for addresses that never anchored a flow.
        std::optional<std::string> lookupHostname(const std::string& ip) const;

    private:
        FlowAggregator m_flowAggregator;
        HostnameCache m_hostnameCache;
        TlsReassembler m_tlsReassembler;
        QuicTracker m_quicTracker;
        ProcessResolver m_processResolver;

        bool m_resolveProcesses = true;
        uint64_t m_plaintextDnsResponses = 0;
        uint64_t m_encryptedDnsPackets = 0;
        bool m_echAdvertised = false;
    };

} // namespace core
