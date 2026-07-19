#pragma once

#include "capture/ICaptureBackend.hpp"
#include "core/LinkType.hpp"

#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace core {
    class PacketQueue;
}


namespace capture {

    class CaptureEngine {
    public:
        explicit CaptureEngine(core::PacketQueue& queue);
        ~CaptureEngine();

        std::vector<DeviceInfo> getAvailableDevices() const;
        void startCapture(const std::string& deviceName);
        bool openFile(const std::string& path);

        // True once a live capture has been started successfully. Note that a
        // capture which started and then ended (adapter unplugged, end of a
        // replayed source) still reads as true; this answers "did we get off
        // the ground", not "is traffic still arriving".
        bool isCapturing() const { return m_captureThread.joinable(); }

        // Reads an offline capture start to finish, handing each packet to
        // `onPacket` as it is read.
        //
        // Unlike openFile(), packets never pass through the bounded
        // PacketQueue, which drops its oldest entries once full. A capture
        // with more packets than the queue holds would otherwise lose the
        // beginning of the file before anything could consume it — silently
        // wrong totals, which is unacceptable when the output is an exported
        // flow table.
        bool replayFile(const std::string& path,
            const std::function<void(const core::PacketData&)>& onPacket,
            std::string& error);
        bool setFilter(const std::string& filter, std::string& error);
        bool exportSession(const std::string& path, std::string& error) const;
        void stopCapture();

        // Link-layer encapsulation of the packets currently in the session.
        core::LinkType linkType() const;

    private:
        core::PacketQueue& m_queue;
        std::unique_ptr<ICaptureBackend> m_backend;
        std::thread m_captureThread;
        std::atomic_bool m_stopRequested = false;
        std::string m_currentDevice;
        std::string m_activeFilter;
        std::deque<core::PacketData> m_sessionPackets;
        mutable std::mutex m_sessionMutex;
        // Snapshotted at open() so exportSession() can write the correct DLT
        // even after the handle has been closed.
        std::atomic<core::LinkType> m_sessionLinkType{core::LinkType::Ethernet};

        static constexpr size_t maxSessionPackets = 10'000;

        void captureLoop();
        void clearSession();
        void retainPacket(const core::PacketData& packet);
        void consumePacket(core::PacketData&& packet);
    };

} // namespace capture
