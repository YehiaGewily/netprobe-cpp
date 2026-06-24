#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace core {

    // QUIC v1 (RFC 9000/9001) Initial-packet parser focused on a single job:
    // pulling the SNI out of a client's first flight. The Initial packet is
    // encrypted with keys derived from the public Destination Connection ID,
    // so anyone observing the packet on the wire can decrypt it — but they
    // still need the crypto primitives. mbedTLS provides those.
    //
    // Not a full QUIC stack: we only handle the Long Header Initial packet
    // type, version 1 (0x00000001), and ignore anything else (0-RTT,
    // Handshake, Short Header, Retry, Version Negotiation, drafts).
    class QuicParser {
    public:
        // Returns the SNI from a QUIC Client Initial packet, or std::nullopt if
        // `data` is not a QUIC v1 Initial, doesn't contain a TLS ClientHello,
        // or any step (header parse / key derivation / GCM decrypt / TLS
        // extension walk) fails.
        static std::optional<std::string> extractInitialSni(const uint8_t* data, std::size_t size);
    };

} // namespace core
