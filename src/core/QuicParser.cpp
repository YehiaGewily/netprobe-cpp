#include "core/QuicParser.hpp"

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#include <cstring>
#include <vector>

namespace core {

    namespace {

        // RFC 9001 §5.2 — the salt used to derive QUIC v1 Initial secrets.
        constexpr uint8_t kInitialSaltV1[20] = {
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a
        };

        struct InitialKeys {
            uint8_t key[16]; // AES-128 key for GCM payload encryption
            uint8_t iv[12];  // GCM nonce baseline (XORed with packet number)
            uint8_t hp[16];  // AES-128 key for header protection
        };

        // Read a QUIC variable-length integer (RFC 9000 §16) at `pos`, advancing
        // pos on success. Returns false if the encoded length runs past `size`.
        bool readVarint(const uint8_t* data, size_t size, size_t& pos, uint64_t& out) {
            if (pos >= size) return false;
            const uint8_t first = data[pos];
            const size_t len = static_cast<size_t>(1u) << (first >> 6);
            if (pos + len > size) return false;
            out = first & 0x3F;
            for (size_t i = 1; i < len; ++i) {
                out = (out << 8) | data[pos + i];
            }
            pos += len;
            return true;
        }

        bool hkdfExtract(const uint8_t* salt, size_t saltLen,
                         const uint8_t* ikm, size_t ikmLen,
                         uint8_t outPrk[32]) {
            const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            return md != nullptr
                && mbedtls_hkdf_extract(md, salt, saltLen, ikm, ikmLen, outPrk) == 0;
        }

        // HKDF-Expand-Label per RFC 8446 §7.1 (TLS 1.3). QUIC uses the unmodified
        // TLS 1.3 KDF, so the label prefix is the literal ASCII "tls13 ".
        bool hkdfExpandLabel(const uint8_t* secret, size_t secretLen,
                             const char* label, size_t labelLen,
                             uint8_t* out, size_t outLen) {
            static constexpr char kPrefix[] = "tls13 ";
            constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
            const size_t fullLabelLen = kPrefixLen + labelLen;
            if (fullLabelLen > 255) return false;

            uint8_t info[2 + 1 + 255 + 1] = {};
            size_t p = 0;
            info[p++] = static_cast<uint8_t>(outLen >> 8);
            info[p++] = static_cast<uint8_t>(outLen);
            info[p++] = static_cast<uint8_t>(fullLabelLen);
            std::memcpy(info + p, kPrefix, kPrefixLen); p += kPrefixLen;
            std::memcpy(info + p, label, labelLen);     p += labelLen;
            info[p++] = 0; // context: empty

            const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            return md != nullptr
                && mbedtls_hkdf_expand(md, secret, secretLen, info, p, out, outLen) == 0;
        }

        bool deriveClientInitialKeys(const uint8_t* dcid, size_t dcidLen, InitialKeys& out) {
            uint8_t initialSecret[32];
            if (!hkdfExtract(kInitialSaltV1, sizeof(kInitialSaltV1), dcid, dcidLen, initialSecret)) {
                return false;
            }
            uint8_t clientSecret[32];
            if (!hkdfExpandLabel(initialSecret, 32, "client in", 9, clientSecret, 32)) return false;
            if (!hkdfExpandLabel(clientSecret, 32, "quic key", 8, out.key, 16)) return false;
            if (!hkdfExpandLabel(clientSecret, 32, "quic iv", 7, out.iv, 12)) return false;
            if (!hkdfExpandLabel(clientSecret, 32, "quic hp", 7, out.hp, 16)) return false;
            return true;
        }

        // Compute the 5-byte header-protection mask (one AES-ECB block on the
        // sample), then unmask the first byte's low nibble and the packet number.
        bool removeHeaderProtection(const InitialKeys& keys,
                                    const uint8_t* sample,
                                    uint8_t& inOutFirstByte,
                                    uint8_t pnBytes[4],
                                    size_t& outPnLen) {
            uint8_t mask[16] = {};
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            bool ok = false;
            if (mbedtls_aes_setkey_enc(&ctx, keys.hp, 128) == 0
                && mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, sample, mask) == 0) {
                ok = true;
            }
            mbedtls_aes_free(&ctx);
            if (!ok) return false;

            // Long header: low nibble (bits 0..3) is masked.
            inOutFirstByte ^= (mask[0] & 0x0F);
            outPnLen = static_cast<size_t>(inOutFirstByte & 0x03) + 1;
            for (size_t i = 0; i < outPnLen; ++i) {
                pnBytes[i] ^= mask[i + 1];
            }
            return true;
        }

        // AES-128-GCM decrypt with QUIC's nonce = iv XOR packet_number (PN
        // big-endian, right-aligned to 12 bytes).
        bool decryptPayload(const InitialKeys& keys,
                            uint64_t packetNumber,
                            const uint8_t* aad, size_t aadLen,
                            const uint8_t* ciphertext, size_t ciphertextLen,
                            const uint8_t* tag,
                            std::vector<uint8_t>& outPlaintext) {
            if (ciphertextLen == 0) return false;
            uint8_t nonce[12];
            std::memcpy(nonce, keys.iv, 12);
            for (int i = 0; i < 8; ++i) {
                nonce[12 - 1 - i] ^= static_cast<uint8_t>((packetNumber >> (i * 8)) & 0xFFu);
            }

            outPlaintext.resize(ciphertextLen);
            mbedtls_gcm_context ctx;
            mbedtls_gcm_init(&ctx);
            int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, keys.key, 128);
            if (rc == 0) {
                rc = mbedtls_gcm_auth_decrypt(&ctx, ciphertextLen,
                    nonce, sizeof(nonce),
                    aad, aadLen,
                    tag, 16,
                    ciphertext, outPlaintext.data());
            }
            mbedtls_gcm_free(&ctx);
            return rc == 0;
        }

        // Walk the decrypted Initial payload, collecting CRYPTO frames into a
        // contiguous TLS handshake stream by offset. Skips PADDING/PING/ACK; any
        // other frame type causes us to bail (we shouldn't see those in a client
        // Initial that contains the ClientHello).
        bool reassembleCryptoStream(const uint8_t* plaintext, size_t len,
                                    std::vector<uint8_t>& outStream) {
            size_t pos = 0;
            while (pos < len) {
                const uint8_t frameType = plaintext[pos++];
                switch (frameType) {
                case 0x00: // PADDING
                case 0x01: // PING
                    break;
                case 0x02:   // ACK
                case 0x03: { // ACK with ECN counts
                    uint64_t largestAck, ackDelay, rangeCount, firstRange;
                    if (!readVarint(plaintext, len, pos, largestAck)) return false;
                    if (!readVarint(plaintext, len, pos, ackDelay))   return false;
                    if (!readVarint(plaintext, len, pos, rangeCount)) return false;
                    if (!readVarint(plaintext, len, pos, firstRange)) return false;
                    for (uint64_t i = 0; i < rangeCount; ++i) {
                        uint64_t gap, rangeLen;
                        if (!readVarint(plaintext, len, pos, gap))      return false;
                        if (!readVarint(plaintext, len, pos, rangeLen)) return false;
                    }
                    if (frameType == 0x03) {
                        uint64_t ect0, ect1, ecnce;
                        if (!readVarint(plaintext, len, pos, ect0))  return false;
                        if (!readVarint(plaintext, len, pos, ect1))  return false;
                        if (!readVarint(plaintext, len, pos, ecnce)) return false;
                    }
                    break;
                }
                case 0x06: { // CRYPTO
                    uint64_t offset = 0, dataLen = 0;
                    if (!readVarint(plaintext, len, pos, offset))  return false;
                    if (!readVarint(plaintext, len, pos, dataLen)) return false;
                    if (pos + dataLen > len) return false;
                    if (offset > (1u << 24) || dataLen > (1u << 24)) return false; // sanity cap
                    const size_t end = static_cast<size_t>(offset) + static_cast<size_t>(dataLen);
                    if (outStream.size() < end) outStream.resize(end);
                    std::memcpy(outStream.data() + offset, plaintext + pos, dataLen);
                    pos += dataLen;
                    break;
                }
                default:
                    // CONNECTION_CLOSE, NEW_TOKEN, etc — not expected in a
                    // client Initial. Bail rather than misparse.
                    return false;
                }
            }
            return true;
        }

        // Parse a TLS 1.3 handshake header + ClientHello message and return the
        // SNI hostname, if present.
        std::optional<std::string> extractSniFromClientHello(const uint8_t* data, size_t size) {
            if (size < 4) return std::nullopt;
            if (data[0] != 0x01) return std::nullopt; // not ClientHello
            const size_t bodyLen = (static_cast<size_t>(data[1]) << 16)
                                 | (static_cast<size_t>(data[2]) << 8)
                                 |  static_cast<size_t>(data[3]);
            if (4 + bodyLen > size) return std::nullopt;
            const uint8_t* body = data + 4;
            size_t pos = 0;

            // legacy_version (2) + random (32)
            if (pos + 34 > bodyLen) return std::nullopt;
            pos += 34;

            // session_id<0..32>
            if (pos + 1 > bodyLen) return std::nullopt;
            const uint8_t sidLen = body[pos++];
            if (pos + sidLen > bodyLen) return std::nullopt;
            pos += sidLen;

            // cipher_suites<2..2^16-2>
            if (pos + 2 > bodyLen) return std::nullopt;
            const uint16_t csLen = (static_cast<uint16_t>(body[pos]) << 8) | body[pos + 1];
            pos += 2;
            if (pos + csLen > bodyLen) return std::nullopt;
            pos += csLen;

            // legacy_compression_methods<1..2^8-1>
            if (pos + 1 > bodyLen) return std::nullopt;
            const uint8_t compLen = body[pos++];
            if (pos + compLen > bodyLen) return std::nullopt;
            pos += compLen;

            // extensions<8..2^16-1>
            if (pos + 2 > bodyLen) return std::nullopt;
            const uint16_t extLen = (static_cast<uint16_t>(body[pos]) << 8) | body[pos + 1];
            pos += 2;
            if (pos + extLen > bodyLen) return std::nullopt;
            const uint8_t* p   = body + pos;
            const uint8_t* end = p + extLen;

            while (p + 4 <= end) {
                const uint16_t extType = (static_cast<uint16_t>(p[0]) << 8) | p[1];
                const uint16_t extDataLen = (static_cast<uint16_t>(p[2]) << 8) | p[3];
                p += 4;
                if (p + extDataLen > end) return std::nullopt;

                if (extType == 0x0000) { // server_name (RFC 6066)
                    if (extDataLen < 5) { p += extDataLen; continue; }
                    const uint16_t listLen = (static_cast<uint16_t>(p[0]) << 8) | p[1];
                    if (static_cast<size_t>(listLen) + 2 > extDataLen) { p += extDataLen; continue; }
                    const uint8_t* sl = p + 2;
                    if (listLen < 3) { p += extDataLen; continue; }
                    const uint8_t nameType = sl[0];
                    if (nameType != 0x00) { p += extDataLen; continue; } // host_name
                    const uint16_t nameLen = (static_cast<uint16_t>(sl[1]) << 8) | sl[2];
                    if (static_cast<size_t>(3) + nameLen > listLen) { p += extDataLen; continue; }
                    return std::string(reinterpret_cast<const char*>(sl + 3), nameLen);
                }
                p += extDataLen;
            }
            return std::nullopt;
        }

    } // namespace

    std::optional<std::string> QuicParser::extractInitialSni(const uint8_t* data, size_t size) {
        // Minimum viable Initial: 1 + 4 + 1 + 0 + 1 + 0 + 1 + 1 + 5 + 16 = ~30 bytes.
        // Be generous and just require enough for the fixed header bytes we read
        // before bounds-checking the variable parts.
        if (!data || size < 20) return std::nullopt;

        // Long header (bit 7 = 1) + fixed bit (bit 6 = 1). Type bits 4-5 and
        // packet-number-length bits 0-1 are still encrypted by header protection
        // at this point, so don't check them yet.
        if ((data[0] & 0xC0) != 0xC0) return std::nullopt;

        // Version 1 (QUIC v1, RFC 9000).
        const uint32_t version = (static_cast<uint32_t>(data[1]) << 24)
                               | (static_cast<uint32_t>(data[2]) << 16)
                               | (static_cast<uint32_t>(data[3]) << 8)
                               |  static_cast<uint32_t>(data[4]);
        if (version != 0x00000001) return std::nullopt;

        size_t pos = 5;
        if (pos >= size) return std::nullopt;
        const uint8_t dcidLen = data[pos++];
        if (dcidLen > 20 || pos + dcidLen > size) return std::nullopt;
        const uint8_t* dcid = data + pos;
        pos += dcidLen;

        if (pos >= size) return std::nullopt;
        const uint8_t scidLen = data[pos++];
        if (scidLen > 20 || pos + scidLen > size) return std::nullopt;
        pos += scidLen;

        // Initial packet only: Token Length + Token come before the Length field.
        uint64_t tokenLen = 0;
        if (!readVarint(data, size, pos, tokenLen)) return std::nullopt;
        if (tokenLen > size || pos + tokenLen > size) return std::nullopt;
        pos += static_cast<size_t>(tokenLen);

        uint64_t length = 0;
        if (!readVarint(data, size, pos, length)) return std::nullopt;
        const size_t pnOffset = pos;
        if (pnOffset + length > size) return std::nullopt;
        if (length < 16 + 1) return std::nullopt; // tag + at least 1 PN byte

        // The HP sample is 16 bytes at offset (pnOffset + 4), assuming the
        // longest legal PN length. The actual PN length is recovered from the
        // unprotected first byte.
        if (pnOffset + 4 + 16 > size) return std::nullopt;
        const uint8_t* sample = data + pnOffset + 4;

        InitialKeys keys;
        if (!deriveClientInitialKeys(dcid, dcidLen, keys)) return std::nullopt;

        uint8_t firstByte = data[0];
        uint8_t pnBytes[4];
        std::memcpy(pnBytes, data + pnOffset, 4);

        size_t pnLen = 0;
        if (!removeHeaderProtection(keys, sample, firstByte, pnBytes, pnLen)) {
            return std::nullopt;
        }

        // After HP removal, type bits 4-5 must be 00 for an Initial packet.
        if ((firstByte & 0x30) != 0x00) return std::nullopt;
        if (pnLen == 0 || pnLen > 4) return std::nullopt;

        uint64_t packetNumber = 0;
        for (size_t i = 0; i < pnLen; ++i) {
            packetNumber = (packetNumber << 8) | pnBytes[i];
        }

        // AAD covers the whole unprotected header from byte 0 through the
        // packet number. Rebuild it with the unprotected first byte and PN.
        std::vector<uint8_t> aad(data, data + pnOffset + pnLen);
        aad[0] = firstByte;
        for (size_t i = 0; i < pnLen; ++i) aad[pnOffset + i] = pnBytes[i];

        const size_t payloadStart = pnOffset + pnLen;
        const size_t payloadEnd   = pnOffset + static_cast<size_t>(length);
        if (payloadStart + 16 > payloadEnd) return std::nullopt;
        const size_t ciphertextLen = payloadEnd - payloadStart - 16;
        const uint8_t* ciphertext = data + payloadStart;
        const uint8_t* tag        = data + payloadEnd - 16;

        std::vector<uint8_t> plaintext;
        if (!decryptPayload(keys, packetNumber, aad.data(), aad.size(),
                            ciphertext, ciphertextLen, tag, plaintext)) {
            return std::nullopt;
        }

        std::vector<uint8_t> tlsStream;
        if (!reassembleCryptoStream(plaintext.data(), plaintext.size(), tlsStream)) {
            return std::nullopt;
        }
        if (tlsStream.empty()) return std::nullopt;

        return extractSniFromClientHello(tlsStream.data(), tlsStream.size());
    }

} // namespace core
