#pragma once

#include "core/PacketData.hpp"

#include <memory>
#include <string>
#include <vector>

namespace capture {

    struct DeviceInfo {
        std::string name;
        std::string description;
    };

    enum class PacketReadStatus {
        Packet,
        Timeout,
        EndOfFile,
        Error,
    };

    class ICaptureBackend {
    public:
        virtual ~ICaptureBackend() = default;

        virtual std::vector<DeviceInfo> listDevices(std::string& error) const = 0;
        virtual bool open(const std::string& deviceName, std::string& error) = 0;
        virtual bool openFile(const std::string& path, std::string& error) = 0;
        virtual bool setFilter(const std::string& filter, std::string& error) = 0;
        virtual PacketReadStatus nextPacket(core::PacketData& packet, std::string& error) = 0;
        virtual void close() = 0;
        virtual bool isOpen() const = 0;
    };

    std::unique_ptr<ICaptureBackend> createPlatformCaptureBackend();

} // namespace capture
