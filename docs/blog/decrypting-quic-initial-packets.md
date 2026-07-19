# Decrypting QUIC Initial packets by hand

*How a passive analyzer recovers the server name from an encrypted QUIC handshake: HKDF, header protection, AES-GCM, and CRYPTO reassembly.*

---

## Why this is worth explaining

If you run a packet analyzer on a modern network, a growing share of your traffic is QUIC, and QUIC looks like noise. TLS over TCP at least hands you a plaintext ClientHello: the SNI is sitting there in the clear, and any tool can read it. QUIC encrypts its handshake from the very first packet. Point Wireshark at a QUIC flow without keys and you get UDP payloads of undifferentiated bytes.

Except it isn't really undifferentiated, because QUIC's *Initial* packets are encrypted with keys derived from a value that is printed in the clear in the packet header. This is not a flaw — the encryption exists to stop middleboxes ossifying the protocol, not to hide anything from an observer — but it means a passive analyzer *can* decrypt Initial packets and read the ClientHello inside.

Very few people write this up accessibly. The RFCs describe it precisely and unhelpfully; most blog posts stop at "QUIC encrypts its handshake." This post walks the entire path in the order the code executes, using [NetProbe](https://github.com/YehiaGewily/netprobe-cpp)'s implementation in [`src/core/QuicParser.cpp`](../../src/core/QuicParser.cpp) as the worked example.

The five stages:

1. Parse enough of the long header to find the Destination Connection ID
2. Derive Initial secrets from that DCID (HKDF-Extract, then HKDF-Expand-Label)
3. Remove header protection to recover the packet number
4. Decrypt the payload with AES-128-GCM
5. Reassemble CRYPTO frames — possibly across several packets — and parse the ClientHello

Stage 5 is the one most implementations get wrong, and it is the one that matters most in 2026.

---

## Stage 0: the long header

A QUIC Initial packet uses the *long header* form. The first byte tells you which:

```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|1|1|T T|R R|P P|
+-+-+-+-+-+-+-+-+
```

Bit 7 set means long header; bit 6 is the "fixed bit", always 1. NetProbe's cheap pre-filter checks exactly those two bits before doing any work:

```cpp
bool QuicParser::looksLikeLongHeader(const uint8_t* data, size_t size) {
    // Long header (bit 7) + fixed bit (bit 6).
    ...
}
```

This matters for performance. Every UDP packet on the wire gets this test; only the ones that pass go anywhere near the crypto.

After the first byte comes a 32-bit version, then the connection IDs:

```
first byte (1) | version (4) | DCID len (1) | DCID (0-20) | SCID len (1) | SCID (0-20) | token len (varint) | token | length (varint) | packet number (1-4, protected) | payload
```

Two versions matter today:

| Version | Value | Spec |
| --- | --- | --- |
| QUIC v1 | `0x00000001` | RFC 9000 |
| QUIC v2 | `0x6b3343cf` | RFC 9369 |

**The v2 trap.** QUIC v2 is not a cosmetic revision of v1. It uses a *different Initial salt* and *different key-derivation labels*. A v1-only parser does not error on v2 — it derives the wrong keys, AES-GCM authentication fails, and the packet is silently discarded as "not decryptable." You get no SNI and no indication why. NetProbe carries both parameter sets:

```cpp
struct VersionParams {
    const uint8_t* salt;
    const char* keyLabel;
    const char* ivLabel;
    const char* hpLabel;
    uint8_t initialTypeBits; // value of (firstByte & 0x30) for an Initial
};

// v1: {kInitialSaltV1, "quic key", "quic iv", "quic hp", 0x00}
// v2: {kInitialSaltV2, "quicv2 key", "quicv2 iv", "quicv2 hp", 0x10}
```

Note the last field. The two-bit packet *type* encoding also changed between versions: an Initial is `0b00` in v1 and `0b01` in v2. Hardcode the v1 value and you will reject every v2 Initial before you even get to the keys.

---

## Stage 1: deriving keys from a public value

Here is the part that surprises people. The Initial keys come from the **Destination Connection ID**, which is transmitted in plaintext in the header of the very packet you are trying to decrypt.

RFC 9001 §5.2 defines:

```
initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
```

The salt is a fixed 20-byte constant published in the RFC. For v1 it begins `0x38 0x76 0x2c 0xf7 …`. So the "secret" is derived from a public constant and a public field. Anyone observing the packet can compute it.

That is deliberate. The purpose of Initial encryption is to make the handshake opaque to middleboxes so they cannot come to depend on its internals and freeze the protocol in place — not to provide confidentiality against an observer. Real confidentiality begins with the Handshake keys, which come from the ephemeral key exchange inside the ClientHello. Those you cannot derive passively, and NetProbe does not try.

From the initial secret, one more expansion gives the client's secret:

```
client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
```

Then three more give the actual key material:

```
key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)   // AES-128
iv  = HKDF-Expand-Label(client_initial_secret, "quic iv",  "", 12)   // GCM nonce base
hp  = HKDF-Expand-Label(client_initial_secret, "quic hp",  "", 16)   // header protection
```

In code, that whole chain is:

```cpp
bool deriveClientInitialKeys(const VersionParams& params,
                             const uint8_t* dcid, size_t dcidLen, InitialKeys& out) {
    uint8_t initialSecret[32];
    if (!hkdfExtract(params.salt, 20, dcid, dcidLen, initialSecret)) return false;

    uint8_t clientSecret[32];
    if (!hkdfExpandLabel(initialSecret, 32, "client in", 9, clientSecret, 32)) return false;

    if (!hkdfExpandLabel(clientSecret, 32, params.keyLabel, ..., out.key, 16)) return false;
    if (!hkdfExpandLabel(clientSecret, 32, params.ivLabel,  ..., out.iv,  12)) return false;
    if (!hkdfExpandLabel(clientSecret, 32, params.hpLabel,  ..., out.hp,  16)) return false;
    return true;
}
```

### HKDF-Expand-Label is not HKDF-Expand

This trips people up. `HKDF-Expand-Label` is a TLS 1.3 construction (RFC 8446 §7.1) that builds a structured `info` parameter before calling ordinary HKDF-Expand:

```
struct {
    uint16 length;
    opaque label<7..255>;   // "tls13 " || label
    opaque context<0..255>;
} HkdfLabel;
```

The literal ASCII prefix `"tls13 "` — with the trailing space — is prepended to every label. QUIC uses the TLS 1.3 KDF unmodified, so `"quic key"` is really `"tls13 quic key"` on the wire:

```cpp
static constexpr char kPrefix[] = "tls13 ";
...
info[p++] = static_cast<uint8_t>(outLen >> 8);
info[p++] = static_cast<uint8_t>(outLen);
info[p++] = static_cast<uint8_t>(fullLabelLen);
std::memcpy(info + p, kPrefix, kPrefixLen); p += kPrefixLen;
std::memcpy(info + p, label, labelLen);     p += labelLen;
info[p++] = 0x00;  // empty context
```

Forget the prefix, or the two-byte big-endian output length, or the trailing empty-context byte, and you get 16 perfectly valid-looking bytes that decrypt nothing. There is no diagnostic. This is the single most common place to lose an afternoon.

---

## Stage 2: the chicken-and-egg of header protection

You now have keys. You cannot yet decrypt, because you do not know where the ciphertext starts.

The packet number is 1–4 bytes, and *how many* is encoded in the low two bits of the first byte — which is itself encrypted. Worse, the packet number is an input to the AEAD nonce. So:

- To find the packet number length, you must decrypt the first byte.
- To decrypt the payload, you need the packet number.

QUIC resolves this with **header protection**: a separate cipher pass that masks only the header bits, keyed by a sample of the ciphertext taken from a position that does not depend on the packet number length.

The trick is that the sample is taken at a *fixed* offset — 4 bytes past where the packet number starts, as though the packet number were always the maximum 4 bytes:

```cpp
// The HP sample is 16 bytes at offset (pnOffset + 4), assuming the
// maximum 4-byte packet number.
```

Encrypt that 16-byte sample with AES-128-ECB under the `hp` key. The output is a 5-byte mask:

```cpp
mbedtls_aes_setkey_enc(&ctx, keys.hp, 128);
mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, sample, mask);

// Long header: the low nibble (bits 0..3) is masked.
inOutFirstByte ^= (mask[0] & 0x0F);
outPnLen = static_cast<size_t>(inOutFirstByte & 0x03) + 1;
for (size_t i = 0; i < outPnLen; ++i) {
    pnBytes[i] ^= mask[i + 1];
}
```

`mask[0]` unmasks the first byte — the low **nibble** for a long header, the low 5 bits for a short header. Once the first byte is clear, its low two bits give the packet number length, and `mask[1..4]` unmask that many packet-number bytes.

Note this is AES-ECB, the mode everyone is told never to use. It is correct here precisely because it is a single block of a value that is never reused: one deterministic permutation of a unique sample. Using it as a general-purpose mode is what's dangerous.

---

## Stage 3: AES-128-GCM, and the nonce that is not the IV

Now the payload. QUIC uses AEAD_AES_128_GCM for Initial packets, with two details that differ from how people usually reach for GCM.

**The nonce is the IV XOR the packet number**, big-endian and right-aligned into 12 bytes:

```cpp
uint8_t nonce[12];
std::memcpy(nonce, keys.iv, 12);
for (int i = 0; i < 8; ++i) {
    nonce[12 - 1 - i] ^= static_cast<uint8_t>((packetNumber >> (i * 8)) & 0xFFu);
}
```

The derived `iv` is not used directly — it is a per-connection baseline that the packet number perturbs, guaranteeing a unique nonce per packet without transmitting one.

**The associated data is the entire header, unprotected.** Everything from the first byte through the end of the packet number, *after* header protection has been removed, is authenticated but not encrypted. Get the AAD boundaries wrong by a single byte and GCM authentication fails with no hint as to why.

The 16-byte authentication tag occupies the last 16 bytes of the payload:

```cpp
mbedtls_gcm_auth_decrypt(&ctx, ciphertextLen,
    nonce, sizeof(nonce),
    aad, aadLen,
    tag, 16,
    ciphertext, outPlaintext.data());
```

This authentication check is doing real work for an analyzer, not just crypto hygiene. Because Initial keys are derivable by anyone, a passive parser will happily attempt decryption on any UDP packet whose first two bits look like a long header. The GCM tag is what distinguishes an actual QUIC Initial from a coincidence. **A failed tag is not an error to report — it is the normal answer for a packet that was never QUIC.**

---

## Stage 4: CRYPTO frames, and the part everyone gets wrong

Decryption gives you a QUIC frame sequence, not a ClientHello. Walk it, collecting CRYPTO frames (type `0x06`) and skipping the frames that legitimately appear in an Initial:

- `0x00` PADDING — usually a *lot* of it, since Initials are padded to at least 1200 bytes
- `0x01` PING
- `0x02`/`0x03` ACK
- `0x06` CRYPTO — carries `offset` and `length` varints, then the TLS bytes

Each CRYPTO frame carries an **offset**. That is the whole story: the ClientHello is a byte stream that may be split across multiple frames, in multiple packets, arriving in any order.

For years you could ignore this. A ClientHello fit comfortably in one Initial packet, so a parser that grabbed the first CRYPTO frame and parsed it worked essentially always.

**That stopped being true.** Post-quantum key exchange — X25519MLKEM768, now the default in Chrome and Firefox — adds roughly a kilobyte to the ClientHello. A post-quantum key share does not fit alongside everything else in a single Initial. Real ClientHellos are now routinely split across two or more Initial packets.

So a parser that reads only the first CRYPTO frame does not fail loudly. It silently stops finding SNI on a steadily growing share of real traffic — exactly the browsers and traffic you most want visibility into. This is the highest-value correctness detail in the entire pipeline, and it is the one most likely to be skipped.

NetProbe handles it in [`QuicTracker`](../../src/core/QuicTracker.cpp), which buffers fragments per connection, keyed by the Destination Connection ID, and reassembles by offset until the TLS record is complete. Because it holds state across packets from the network, it is bounded on every axis:

```cpp
static constexpr size_t kMaxStreamBytes = size_t{64} * 1024;
```

with a cap on tracked connections and a timeout that evicts handshakes that never complete. An attacker who can send packets should not be able to make an analyzer allocate without limit — a reassembler that trusts offsets is a memory-exhaustion primitive wearing a parser costume.

The frame walk applies the same suspicion:

```cpp
constexpr uint64_t kSaneCryptoBound = 1u << 24;
```

A CRYPTO frame claiming a 16 MB length is not a large handshake; it is an attack or a corrupt packet, and either way the right move is to stop.

---

## Stage 5: reading the SNI

With a contiguous ClientHello you are back in ordinary TLS 1.3 territory: skip `legacy_version` (2 bytes) and `random` (32), then the variable-length session ID, cipher suites, and compression methods, to reach the extension list. Find extension type `0x0000`, server_name, and read the first `host_name` entry.

Every one of those length fields comes from the network. Each one gets bounds-checked against the buffer, and any inconsistency aborts the parse rather than clamping and continuing — a parser that "recovers" from a malformed length is a parser that eventually reports a hostname assembled from adjacent memory.

---

## What you end up with

For a passive observer with no keys and no cooperation from either endpoint:

- The server name a QUIC client is connecting to, on any UDP port
- For both QUIC v1 and v2
- Including handshakes split across multiple Initial packets

And what you explicitly do *not* get: anything after the Initial. Handshake and 1-RTT packets are protected by keys derived from the ephemeral exchange, and no amount of passive observation recovers them. That boundary is worth stating plainly, because the ability to decrypt Initials is sometimes mistaken for a break in QUIC's confidentiality. It is not. It is a deliberate design point, and the visibility it gives you ends exactly where real encryption begins.

There is also a live counter-pressure worth knowing about: **Encrypted Client Hello**. When ECH is in use the true server name is encrypted inside an outer ClientHello, and none of the above recovers it. NetProbe detects advertised ECH configs in DNS HTTPS records and reports that name resolution has genuinely moved out of view, rather than showing a bare IP and letting you assume the tool failed.

---

## Testing something you cannot eyeball

Crypto code fails silently. A wrong label, a nonce assembled in the wrong byte order, an AAD off by one — every one of these produces a clean "authentication failed" and no clue. Print-debugging is nearly useless because every intermediate value is uniform-looking bytes.

The only approach that holds up is deriving known-good vectors from the RFC and asserting on each stage independently, so a failure localizes to one transformation. NetProbe's suite covers the full path end-to-end, including a two-packet split ClientHello, and the parsers are continuously fuzzed under ASan/UBSan with a corpus seeded by hand-built adversarial packets: connection ID lengths beyond the packet, token lengths claiming more than exists, truncated varints. That last category matters here more than almost anywhere else in a network tool, because this code path takes attacker-controlled bytes and does pointer arithmetic on lengths derived from them.

---

*The implementation described here is in [`src/core/QuicParser.cpp`](../../src/core/QuicParser.cpp) and [`src/core/QuicTracker.cpp`](../../src/core/QuicTracker.cpp). Corrections welcome — particularly from anyone who has fought the v2 label change.*
