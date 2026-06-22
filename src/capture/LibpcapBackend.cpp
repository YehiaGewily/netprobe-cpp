#include "capture/ICaptureBackend.hpp"
#include "capture/PcapPlatform.hpp"

#ifndef _WIN32

namespace capture {
    namespace {
        class LibpcapBackend final : public ICaptureBackend {
        public:
            ~LibpcapBackend() override { close(); }

            std::vector<DeviceInfo> listDevices(std::string& error) const override {
                std::vector<DeviceInfo> devices;
                pcap_if_t* allDevices = nullptr;
                char errorBuffer[PCAP_ERRBUF_SIZE]{};
                if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
                    error = errorBuffer;
                    return devices;
                }

                for (pcap_if_t* device = allDevices; device; device = device->next) {
                    devices.push_back({device->name ? device->name : "Unknown",
                        device->description ? device->description : "No Description"});
                }
                pcap_freealldevs(allDevices);
                return devices;
            }

            bool open(const std::string& deviceName, std::string& error) override {
                close();
                char errorBuffer[PCAP_ERRBUF_SIZE]{};
                m_handle = pcap_open_live(deviceName.c_str(), 65536, 1, 1000, errorBuffer);
                if (!m_handle) error = errorBuffer;
                return m_handle != nullptr;
            }

            bool openFile(const std::string& path, std::string& error) override {
                close();
                char errorBuffer[PCAP_ERRBUF_SIZE]{};
                m_handle = pcap_open_offline(path.c_str(), errorBuffer);
                if (!m_handle) error = errorBuffer;
                return m_handle != nullptr;
            }

            bool setFilter(const std::string& filter, std::string& error) override {
                if (!m_handle) {
                    error = "Capture handle is not open.";
                    return false;
                }
                bpf_program program{};
                const char* expression = filter.empty() ? "len >= 0" : filter.c_str();
                if (pcap_compile(m_handle, &program, expression, 1, PCAP_NETMASK_UNKNOWN) == -1) {
                    error = pcap_geterr(m_handle);
                    return false;
                }
                const int result = pcap_setfilter(m_handle, &program);
                pcap_freecode(&program);
                if (result == -1) error = pcap_geterr(m_handle);
                return result != -1;
            }

            PacketReadStatus nextPacket(core::PacketData& packet, std::string& error) override {
                pcap_pkthdr* header = nullptr;
                const unsigned char* bytes = nullptr;
                const int result = pcap_next_ex(m_handle, &header, &bytes);
                if (result == 1) {
                    const int64_t timestamp = static_cast<int64_t>(header->ts.tv_sec) * 1'000'000 + header->ts.tv_usec;
                    packet = core::PacketData(timestamp, header->len, header->caplen, bytes);
                    return PacketReadStatus::Packet;
                }
                if (result == 0) return PacketReadStatus::Timeout;
                if (result == -2) return PacketReadStatus::EndOfFile;
                error = m_handle ? pcap_geterr(m_handle) : "Capture handle is not open.";
                return PacketReadStatus::Error;
            }

            void close() override {
                if (m_handle) {
                    pcap_close(m_handle);
                    m_handle = nullptr;
                }
            }

            bool isOpen() const override { return m_handle != nullptr; }

        private:
            pcap_t* m_handle = nullptr;
        };
    }

    std::unique_ptr<ICaptureBackend> createPlatformCaptureBackend() {
        return std::make_unique<LibpcapBackend>();
    }
} // namespace capture

#endif
