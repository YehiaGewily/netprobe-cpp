#pragma once

#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <functional>

// Forward declaration for pcap types to avoid including pcap.h in header
struct pcap;
typedef struct pcap pcap_t;
struct pcap_pkthdr;

namespace core {
    class PacketQueue;
}

namespace capture {

    struct DeviceInfo {
        std::string name;
        std::string description;
    };

    class CaptureEngine {
    public:
        // Constructor takes a reference to the queue where packets will be pushed
        explicit CaptureEngine(core::PacketQueue& queue);
        ~CaptureEngine();

        // Accesses network adapters using pcap_findalldevs_ex
        std::vector<DeviceInfo> getAvailableDevices() const;

        // Starts capture on the specified device in a background thread
        void startCapture(const std::string& deviceName);

        // Stops the active capture
        void stopCapture();

    private:
        core::PacketQueue& m_queue;
        pcap_t* m_handle = nullptr;
        std::jthread m_captureThread;
        std::string m_currentDevice;
        
        // Internal capture loop
        void captureLoop(std::stop_token stoken);
        
        static void packetHandler(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet);
    };

} // namespace capture
