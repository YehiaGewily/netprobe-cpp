#include "capture/CaptureEngine.hpp"
#include "capture/PcapPlatform.hpp"
#include "core/PacketQueue.hpp"

#include <iostream>
#include <vector>

namespace capture {

    CaptureEngine::CaptureEngine(core::PacketQueue& queue)
        : m_queue(queue)
        , m_backend(createPlatformCaptureBackend()) {}

    CaptureEngine::~CaptureEngine() {
        stopCapture();
    }

    std::vector<DeviceInfo> CaptureEngine::getAvailableDevices() const {
        std::string error;
        auto devices = m_backend->listDevices(error);
        if (!error.empty()) std::cerr << "Unable to list capture devices: " << error << std::endl;
        return devices;
    }

    void CaptureEngine::startCapture(const std::string& deviceName) {
        stopCapture();
        m_queue.clear();
        clearSession();
        m_currentDevice = deviceName;

        std::string error;
        if (!m_backend->open(deviceName, error)) {
            std::cerr << "Unable to open adapter " << deviceName << ": " << error << std::endl;
            return;
        }
        if (!m_activeFilter.empty() && !m_backend->setFilter(m_activeFilter, error)) {
            std::cerr << "Unable to apply BPF filter '" << m_activeFilter << "': " << error << std::endl;
            m_backend->close();
            return;
        }

        m_stopRequested.store(false, std::memory_order_release);
        m_captureThread = std::thread([this] { captureLoop(); });
    }

    bool CaptureEngine::openFile(const std::string& path) {
        stopCapture();
        m_queue.clear();
        clearSession();
        m_currentDevice.clear();

        std::string error;
        if (!m_backend->openFile(path, error)) {
            std::cerr << "Unable to open capture file '" << path << "': " << error << std::endl;
            return false;
        }

        bool succeeded = true;
        while (true) {
            core::PacketData packet;
            switch (m_backend->nextPacket(packet, error)) {
            case PacketReadStatus::Packet:
                consumePacket(std::move(packet));
                break;
            case PacketReadStatus::Timeout:
                break;
            case PacketReadStatus::EndOfFile:
                m_backend->close();
                return succeeded;
            case PacketReadStatus::Error:
                std::cerr << "Error while reading capture file '" << path << "': " << error << std::endl;
                succeeded = false;
                m_backend->close();
                return succeeded;
            }
        }
    }

    bool CaptureEngine::setFilter(const std::string& filter, std::string& error) {
        if (!m_captureThread.joinable() || !m_backend->isOpen()) {
            error = "A live capture must be running before a BPF filter can be applied.";
            return false;
        }
        if (!m_backend->setFilter(filter, error)) return false;
        m_activeFilter = filter;
        return true;
    }

    bool CaptureEngine::exportSession(const std::string& path, std::string& error) const {
        std::vector<core::PacketData> packets;
        {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            packets.assign(m_sessionPackets.begin(), m_sessionPackets.end());
        }

        pcap_t* deadHandle = pcap_open_dead(DLT_EN10MB, 65536);
        if (!deadHandle) {
            error = "Unable to create a PCAP writer.";
            return false;
        }
        pcap_dumper_t* dumper = pcap_dump_open(deadHandle, path.c_str());
        if (!dumper) {
            error = pcap_geterr(deadHandle);
            pcap_close(deadHandle);
            return false;
        }

        static const uint8_t emptyPacket = 0;
        for (const auto& packet : packets) {
            pcap_pkthdr header{};
            header.ts.tv_sec = static_cast<long>(packet.timestamp / 1'000'000);
            header.ts.tv_usec = static_cast<long>(packet.timestamp % 1'000'000);
            header.caplen = static_cast<bpf_u_int32>(packet.payload.size());
            header.len = static_cast<bpf_u_int32>(packet.length);
            const auto* bytes = packet.payload.empty() ? &emptyPacket : packet.payload.data();
            pcap_dump(reinterpret_cast<unsigned char*>(dumper), &header, bytes);
        }

        pcap_dump_close(dumper);
        pcap_close(deadHandle);
        return true;
    }

    void CaptureEngine::stopCapture() {
        if (m_captureThread.joinable()) {
            m_stopRequested.store(true, std::memory_order_release);
            m_captureThread.join();
        }
        m_backend->close();
    }

    void CaptureEngine::captureLoop() {
        while (!m_stopRequested.load(std::memory_order_acquire)) {
            core::PacketData packet;
            std::string error;
            switch (m_backend->nextPacket(packet, error)) {
            case PacketReadStatus::Packet:
                consumePacket(std::move(packet));
                break;
            case PacketReadStatus::Timeout:
                break;
            case PacketReadStatus::EndOfFile:
                return;
            case PacketReadStatus::Error:
                if (!m_stopRequested.load(std::memory_order_acquire)) {
                    std::cerr << "Capture error: " << error << std::endl;
                }
                return;
            }
        }
    }

    void CaptureEngine::clearSession() {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_sessionPackets.clear();
    }

    void CaptureEngine::retainPacket(const core::PacketData& packet) {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        if (m_sessionPackets.size() >= maxSessionPackets) m_sessionPackets.pop_front();
        m_sessionPackets.push_back(packet);
    }

    void CaptureEngine::consumePacket(core::PacketData&& packet) {
        retainPacket(packet);
        m_queue.push(std::move(packet));
    }

} // namespace capture
