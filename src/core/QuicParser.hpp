#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace core {

    // QUIC Initial-packet parser focused on a single job: pulling the SNI out of
    // a client's first flight. The Initial packet is encrypted with keys derived
    // from the public Destination Connection ID, so anyone observing the packet
    // on the wire can decrypt it — but they still need the crypto primitives.
    // mbedTLS provides those.
    //
    // Not a full QUIC stack: we handle Long Header Initial packets for QUIC v1
    // (RFC 9000/9001) and v2 (RFC 9369), and ignore everything else (0-RTT,
    // Handshake, Short Header, Retry, Version Negotiation, drafts).
    class QuicParser {
    public:
        // One CRYPTO frame's contribution to the TLS handshake stream.
        struct CryptoFragment {
            uint64_t offset = 0;
            std::vector<uint8_t> data;
        };

        // A decrypted client Initial: the connection id that keys the flow, plus
        // the CRYPTO fragments it carried. A ClientHello too large for one packet
        // (a post-quantum key share pushes it well past 1200 bytes) arrives as
        // several Initials whose fragments must be stitched together.
        struct InitialPacket {
            std::vector<uint8_t> destinationConnectionId;
            std::vector<CryptoFragment> crypto;
        };

        // Cheap pre-filter: Long Header bit + Fixed bit set, and a version we
        // know how to decrypt. Safe to call on any UDP payload.
        static bool looksLikeLongHeader(const uint8_t* data, std::size_t size);

        // Decrypts a client Initial and returns its CRYPTO fragment. Returns
        // std::nullopt when `data` is not a QUIC Initial we support, or any step
        // (header parse / key derivation / GCM decrypt / frame walk) fails.
        static std::optional<InitialPacket> parseInitial(const uint8_t* data, std::size_t size);

        // Convenience wrapper: parse a single Initial and, if it happens to
        // carry a complete ClientHello starting at offset 0, return its SNI.
        // Use QuicTracker when the ClientHello may span multiple packets.
        static std::optional<std::string> extractInitialSni(const uint8_t* data, std::size_t size);

        // Extracts the SNI from a complete TLS ClientHello handshake message.
        static std::optional<std::string> sniFromClientHello(const uint8_t* data, std::size_t size);
    };

} // namespace core
