#define HAVE_REMOTE
#include "capture/CaptureEngine.hpp"
#include "core/PacketQueue.hpp"
#include <pcap.h>
#include <iostream>

namespace capture {

    CaptureEngine::CaptureEngine(core::PacketQueue& queue)
        : m_queue(queue)
    {
    }

    CaptureEngine::~CaptureEngine() {
        stopCapture();
    }

    std::vector<DeviceInfo> CaptureEngine::getAvailableDevices() const {
        std::vector<DeviceInfo> devices;
        pcap_if_t* alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        // Retrieve the device list from the local machine
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
            std::cerr << "Error in pcap_findalldevs_ex: " << errbuf << std::endl;
            return devices;
        }

        for (pcap_if_t* d = alldevs; d; d = d->next) {
            std::string name = d->name ? d->name : "Unknown";
            std::string desc = d->description ? d->description : "No Description";
            devices.push_back({name, desc});
        }

        pcap_freealldevs(alldevs);
        return devices;
    }

    void CaptureEngine::startCapture(const std::string& deviceName) {
        stopCapture(); // Ensure any previous session is closed

        m_currentDevice = deviceName;
        char errbuf[PCAP_ERRBUF_SIZE];

        // Open the adapter
        // Snaplen 65536, Promiscuous Mode, 1000ms read timeout
        m_handle = pcap_open(deviceName.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

        if (m_handle == NULL) {
            std::cerr << "Unable to open adapter " << deviceName << ". Error: " << errbuf << std::endl;
            return;
        }

        // Start the capture thread
        m_captureThread = std::jthread([this](std::stop_token stoken) {
            this->captureLoop(stoken);
        });
    }

    void CaptureEngine::stopCapture() {
        // Request stop via jthread destructor or explicit request
        if (m_captureThread.joinable()) {
            m_captureThread.request_stop();
            // We must break the loop manually if it's stuck in pcap_loop
            if (m_handle) {
                pcap_breakloop(m_handle);
            }
            m_captureThread.join();
        }

        if (m_handle) {
            pcap_close(m_handle);
            m_handle = nullptr;
        }
    }

    void CaptureEngine::captureLoop(std::stop_token stoken) {
        if (!m_handle) return;

        // Register a stop callback to break the pcap loop immediately when stop is requested
        std::stop_callback callback(stoken, [this]() {
            if (m_handle) {
                pcap_breakloop(m_handle);
            }
        });

        // Start the capture loop
        // 0 = infinite loop until error or breakloop
        pcap_loop(m_handle, 0, CaptureEngine::packetHandler, reinterpret_cast<unsigned char*>(this));
    }

    void CaptureEngine::packetHandler(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
        auto* engine = reinterpret_cast<CaptureEngine*>(user);
        
        // Convert timestamp struct timeval (sec, usec) to microseconds
        int64_t ts = static_cast<int64_t>(pkthdr->ts.tv_sec) * 1000000 + pkthdr->ts.tv_usec;
        
        // Create PacketData (deep copy of payload)
        core::PacketData data(ts, pkthdr->caplen, packet);
        
        // Push to queue
        engine->m_queue.push(std::move(data));
    }

} // namespace capture
