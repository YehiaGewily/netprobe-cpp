#include "core/AnalysisSession.hpp"

#include "core/DNSParser.hpp"
#include "core/ProtocolParser.hpp"
#include "core/QuicParser.hpp"

#include <algorithm>

namespace core {

    AnalysisSession::AnalysisSession(bool resolveProcesses)
        : m_resolveProcesses(resolveProcesses) {}

    AnalysisSession::Result AnalysisSession::feed(const PacketData& packet) {
        Result result;
        result.parsed = ProtocolParser::parse(packet);
        ParsedPacket& parsed = result.parsed;

        // Recover an SNI that the single-packet parse could not see: a
        // ClientHello split across TCP segments, or a QUIC ClientHello split
        // across Initial packets. Both are routine now that post-quantum key
        // shares have pushed the message past one MTU.
        if (parsed.sni.empty() && parsed.payloadLength > 0
            && parsed.payloadOffset < packet.payload.size()) {
            const uint8_t* payload = packet.payload.data() + parsed.payloadOffset;
            const size_t payloadLength = std::min(parsed.payloadLength,
                packet.payload.size() - parsed.payloadOffset);

            std::optional<std::string> recovered;
            if (parsed.protocol == "TCP") {
                recovered = m_tlsReassembler.feed(parsed, payload, payloadLength);
            } else if (parsed.protocol == "UDP"
                && QuicParser::looksLikeLongHeader(payload, payloadLength)) {
                recovered = m_quicTracker.feed(payload, payloadLength, parsed.timestamp);
            }
            if (recovered && !recovered->empty()) {
                parsed.sni = *recovered;
                if (const std::string named = ProtocolParser::identifyService(*recovered);
                    !named.empty()) {
                    parsed.service = named;
                }
            }
        }

        if (const auto dnsResponse = DNSParser::parseResponse(packet, parsed)) {
            ++m_plaintextDnsResponses;
            if (dnsResponse->encryptedClientHelloAdvertised) m_echAdvertised = true;
            for (const auto& answer : dnsResponse->answers) {
                switch (answer.type) {
                case DNSRecordType::A:
                case DNSRecordType::AAAA: {
                    const std::string& hostname = dnsResponse->queryName.empty()
                        ? answer.name
                        : dnsResponse->queryName;
                    m_hostnameCache.store(answer.value, hostname);
                    m_flowAggregator.setHostnameForAddress(answer.value, hostname);
                    break;
                }
                case DNSRecordType::PTR: {
                    // Reverse answers name devices that never appear in a
                    // forward lookup — printers, NAS boxes, the router.
                    if (const auto address = DNSParser::reverseNameToAddress(answer.name)) {
                        m_hostnameCache.store(*address, answer.value);
                        m_flowAggregator.setHostnameForAddress(*address, answer.value);
                    }
                    break;
                }
                default:
                    break;
                }
            }
        }

        if (parsed.service == "DNS-over-HTTPS" || parsed.service == "DNS-over-TLS"
            || parsed.service == "DNS-over-QUIC") {
            ++m_encryptedDnsPackets;
        }

        if (!parsed.sni.empty()) {
            result.hostname = parsed.sni;
        } else if (!parsed.hostname.empty()) {
            result.hostname = parsed.hostname;
        } else if (const auto destinationHostname = m_hostnameCache.lookup(parsed.dstIP)) {
            result.hostname = *destinationHostname;
        } else if (const auto sourceHostname = m_hostnameCache.lookup(parsed.srcIP)) {
            result.hostname = *sourceHostname;
        }

        // Resolve the owning process now, while the socket is almost
        // certainly still in the OS table; both the flow and the caller's
        // packet record cache it so the name survives after a short-lived
        // connection closes.
        if (m_resolveProcesses) {
            result.process = m_processResolver.lookup(parsed);
        }
        m_flowAggregator.update(parsed, result.hostname, result.process);

        return result;
    }

    std::vector<Flow> AnalysisSession::flows(int64_t nowMicroseconds) const {
        return m_flowAggregator.snapshot(nowMicroseconds);
    }

    void AnalysisSession::clear() {
        m_hostnameCache.clear();
        m_flowAggregator.clear();
        m_tlsReassembler.clear();
        m_quicTracker.clear();
        m_plaintextDnsResponses = 0;
        m_encryptedDnsPackets = 0;
        m_echAdvertised = false;
    }

    std::optional<std::string> AnalysisSession::lookupHostname(const std::string& ip) const {
        return m_hostnameCache.lookup(ip);
    }

} // namespace core
