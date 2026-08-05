#include "core/QuicParser.hpp"

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace core {

    namespace {

        constexpr uint32_t kQuicV1 = 0x00000001; // RFC 9000
        constexpr uint32_t kQuicV2 = 0x6b3343cf; // RFC 9369

        // RFC 9001 §5.2 — salt used to derive QUIC v1 Initial secrets.
        constexpr uint8_t kInitialSaltV1[20] = {
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a
        };

        // RFC 9369 §3.3.1 — QUIC v2 uses a different salt *and* different
        // key-derivation labels, so a v1 parser silently fails to decrypt v2.
        constexpr uint8_t kInitialSaltV2[20] = {
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
            0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
            0xf9, 0xbd, 0x2e, 0xd9
        };

        // Per-version constants that differ between v1 and v2.
        struct VersionParams {
            const uint8_t* salt;
            const char* keyLabel;
            const char* ivLabel;
            const char* hpLabel;
            uint8_t initialTypeBits; // value of (firstByte & 0x30) for an Initial
        };

        bool versionParams(uint32_t version, VersionParams& out) {
            if (version == kQuicV1) {
                out = {kInitialSaltV1, "quic key", "quic iv", "quic hp", 0x00};
                return true;
            }
            if (version == kQuicV2) {
                // RFC 9369 §3.2 remaps the long-header type codes: Initial is
                // 0b01 rather than 0b00.
                out = {kInitialSaltV2, "quicv2 key", "quicv2 iv", "quicv2 hp", 0x10};
                return true;
            }
            return false;
        }

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

        uint32_t readU32(const uint8_t* bytes) {
            return (static_cast<uint32_t>(bytes[0]) << 24)
                 | (static_cast<uint32_t>(bytes[1]) << 16)
                 | (static_cast<uint32_t>(bytes[2]) << 8)
                 |  static_cast<uint32_t>(bytes[3]);
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

        bool deriveClientInitialKeys(const VersionParams& params,
                                     const uint8_t* dcid, size_t dcidLen,
                                     InitialKeys& out) {
            uint8_t initialSecret[32];
            if (!hkdfExtract(params.salt, 20, dcid, dcidLen, initialSecret)) return false;

            uint8_t clientSecret[32];
            if (!hkdfExpandLabel(initialSecret, 32, "client in", 9, clientSecret, 32)) return false;
            if (!hkdfExpandLabel(clientSecret, 32, params.keyLabel,
                    std::strlen(params.keyLabel), out.key, 16)) return false;
            if (!hkdfExpandLabel(clientSecret, 32, params.ivLabel,
                    std::strlen(params.ivLabel), out.iv, 12)) return false;
            if (!hkdfExpandLabel(clientSecret, 32, params.hpLabel,
                    std::strlen(params.hpLabel), out.hp, 16)) return false;
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

        // Walk the decrypted Initial payload, collecting CRYPTO frames. Skips
        // PADDING/PING/ACK; any other frame type causes us to bail (we shouldn't
        // see those in a client Initial that contains the ClientHello).
        bool collectCryptoFrames(const uint8_t* plaintext, size_t len,
                                 std::vector<QuicParser::CryptoFragment>& out) {
            constexpr uint64_t kSaneCryptoBound = 1u << 24;
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
                    if (rangeCount > len) return false; // bound the loop below
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
                    if (dataLen > len - pos) return false;
                    if (offset > kSaneCryptoBound || dataLen > kSaneCryptoBound) return false;
                    QuicParser::CryptoFragment fragment;
                    fragment.offset = offset;
                    fragment.data.assign(plaintext + pos, plaintext + pos + dataLen);
                    out.push_back(std::move(fragment));
                    pos += static_cast<size_t>(dataLen);
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

    } // namespace

    bool QuicParser::looksLikeLongHeader(const uint8_t* data, size_t size) {
        // Long header (bit 7) + fixed bit (bit 6). Type and packet-number-length
        // bits are still header-protected, so they cannot be checked yet.
        if (!data || size < 5) return false;
        if ((data[0] & 0xC0) != 0xC0) return false;
        VersionParams unused;
        return versionParams(readU32(data + 1), unused);
    }

    std::optional<std::string> QuicParser::sniFromClientHello(const uint8_t* data, size_t size) {
        if (!data || size < 4) return std::nullopt;
        if (data[0] != 0x01) return std::nullopt; // not ClientHello
        const size_t bodyLen = (static_cast<size_t>(data[1]) << 16)
                             | (static_cast<size_t>(data[2]) << 8)
                             |  static_cast<size_t>(data[3]);
        if (4 + bodyLen > size) return std::nullopt; // still reassembling
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

    std::optional<QuicParser::InitialPacket> QuicParser::parseInitial(const uint8_t* data, size_t size) {
        if (!data || size < 20) return std::nullopt;
        if ((data[0] & 0xC0) != 0xC0) return std::nullopt;

        const uint32_t version = readU32(data + 1);
        VersionParams params{};
        if (!versionParams(version, params)) return std::nullopt;

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
        if (!deriveClientInitialKeys(params, dcid, dcidLen, keys)) return std::nullopt;

        uint8_t firstByte = data[0];
        uint8_t pnBytes[4];
        std::memcpy(pnBytes, data + pnOffset, 4);

        size_t pnLen = 0;
        if (!removeHeaderProtection(keys, sample, firstByte, pnBytes, pnLen)) {
            return std::nullopt;
        }

        // After HP removal the type bits must identify an Initial. The encoding
        // differs between v1 (0b00) and v2 (0b01).
        if ((firstByte & 0x30) != params.initialTypeBits) return std::nullopt;
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

        InitialPacket result;
        result.destinationConnectionId.assign(dcid, dcid + dcidLen);
        if (!collectCryptoFrames(plaintext.data(), plaintext.size(), result.crypto)) {
            return std::nullopt;
        }
        return result;
    }

    std::optional<std::string> QuicParser::extractInitialSni(const uint8_t* data, size_t size) {
        const auto initial = parseInitial(data, size);
        if (!initial || initial->crypto.empty()) return std::nullopt;

        // Stitch this packet's fragments together; a ClientHello that spills
        // into further Initials needs QuicTracker instead.
        size_t end = 0;
        for (const auto& fragment : initial->crypto) {
            end = std::max(end, static_cast<size_t>(fragment.offset) + fragment.data.size());
        }
        if (end == 0) return std::nullopt;

        std::vector<uint8_t> stream(end, 0);
        for (const auto& fragment : initial->crypto) {
            std::memcpy(stream.data() + fragment.offset, fragment.data.data(), fragment.data.size());
        }
        return sniFromClientHello(stream.data(), stream.size());
    }

} // namespace core
