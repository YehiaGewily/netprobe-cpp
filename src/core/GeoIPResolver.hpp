#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace core {

    struct GeoIPInfo {
        std::string country;
        uint32_t asn = 0;
        std::string organization;
    };

    // Human-readable owner label, e.g. "AS15169 Google LLC", or "-" when the
    // organization is unknown. Shared so the flow table and the exported files
    // cannot disagree about how a network is named.
    std::string organizationLabel(const GeoIPInfo& info);

    class GeoIPResolver {
    public:
        explicit GeoIPResolver(size_t cacheCapacity = 4'096);
        GeoIPResolver(std::filesystem::path countryDatabasePath,
            std::filesystem::path asnDatabasePath, size_t cacheCapacity = 4'096);
        ~GeoIPResolver();

        GeoIPResolver(const GeoIPResolver&) = delete;
        GeoIPResolver& operator=(const GeoIPResolver&) = delete;

        GeoIPInfo lookup(const std::string& ip);
        bool isAvailable() const;
        std::string status() const;

    private:
        struct Database;
        using CacheEntry = std::pair<std::string, GeoIPInfo>;

        std::unique_ptr<Database> m_database;
        size_t m_cacheCapacity;
        std::list<CacheEntry> m_cache;
        std::unordered_map<std::string, std::list<CacheEntry>::iterator> m_cacheIndex;
        mutable std::mutex m_mutex;
    };

} // namespace core
