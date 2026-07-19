#include "core/GeoIPResolver.hpp"

#include <filesystem>
#include <format>
#include <maxminddb.h>

namespace core {

    std::string organizationLabel(const GeoIPInfo& info) {
        if (info.organization.empty()) return std::string{"-"};
        return info.asn == 0
            ? info.organization
            : std::format("AS{} {}", info.asn, info.organization);
    }

    namespace {
        std::filesystem::path geoIpDataDirectory() {
#ifdef NETPROBE_GEOIP_DATA_DIR
            return NETPROBE_GEOIP_DATA_DIR;
#else
            return std::filesystem::current_path() / "data";
#endif
        }

        std::string getUtf8Value(const MMDB_lookup_result_s& result, const char* firstPath, const char* secondPath) {
            MMDB_entry_data_s data{};
            if (MMDB_get_value(const_cast<MMDB_entry_s*>(&result.entry), &data, firstPath, secondPath,
                    static_cast<const char*>(nullptr)) != MMDB_SUCCESS
                || !data.has_data || data.type != MMDB_DATA_TYPE_UTF8_STRING) {
                return {};
            }
            return std::string(reinterpret_cast<const char*>(data.utf8_string), data.data_size);
        }

        uint32_t getUint32Value(const MMDB_lookup_result_s& result, const char* path) {
            MMDB_entry_data_s data{};
            if (MMDB_get_value(const_cast<MMDB_entry_s*>(&result.entry), &data, path,
                    static_cast<const char*>(nullptr)) != MMDB_SUCCESS
                || !data.has_data || data.type != MMDB_DATA_TYPE_UINT32) {
                return 0;
            }
            return data.uint32;
        }
    }

    struct GeoIPResolver::Database {
        MMDB_s country{};
        MMDB_s asn{};
        bool countryOpen = false;
        bool asnOpen = false;
        std::string status;

        Database(const std::filesystem::path& countryPath, const std::filesystem::path& asnPath) {
            countryOpen = MMDB_open(countryPath.string().c_str(), MMDB_MODE_MMAP, &country) == MMDB_SUCCESS;
            asnOpen = MMDB_open(asnPath.string().c_str(), MMDB_MODE_MMAP, &asn) == MMDB_SUCCESS;
            if (countryOpen || asnOpen) {
                status = "GeoLite2 enrichment enabled.";
            } else {
                status = "GeoLite2 databases were not found at " + countryPath.string() + " and " + asnPath.string();
            }
        }

        ~Database() {
            if (countryOpen) MMDB_close(&country);
            if (asnOpen) MMDB_close(&asn);
        }
    };

    GeoIPResolver::GeoIPResolver(size_t cacheCapacity)
        : GeoIPResolver(geoIpDataDirectory() / "GeoLite2-Country.mmdb",
            geoIpDataDirectory() / "GeoLite2-ASN.mmdb", cacheCapacity) {}

    GeoIPResolver::GeoIPResolver(std::filesystem::path countryDatabasePath,
        std::filesystem::path asnDatabasePath, size_t cacheCapacity)
        : m_database(std::make_unique<Database>(countryDatabasePath, asnDatabasePath))
        , m_cacheCapacity(cacheCapacity > 0 ? cacheCapacity : 1) {}

    GeoIPResolver::~GeoIPResolver() = default;

    GeoIPInfo GeoIPResolver::lookup(const std::string& ip) {
        if (ip.empty()) return {};

        std::lock_guard<std::mutex> lock(m_mutex);
        if (const auto cached = m_cacheIndex.find(ip); cached != m_cacheIndex.end()) {
            m_cache.splice(m_cache.begin(), m_cache, cached->second);
            return cached->second->second;
        }

        GeoIPInfo info;
        int gaiError = 0;
        int mmdbError = MMDB_SUCCESS;

        if (m_database->countryOpen) {
            const auto result = MMDB_lookup_string(&m_database->country, ip.c_str(), &gaiError, &mmdbError);
            if (gaiError == 0 && mmdbError == MMDB_SUCCESS && result.found_entry) {
                info.country = getUtf8Value(result, "country", "iso_code");
            }
        }

        gaiError = 0;
        mmdbError = MMDB_SUCCESS;
        if (m_database->asnOpen) {
            const auto result = MMDB_lookup_string(&m_database->asn, ip.c_str(), &gaiError, &mmdbError);
            if (gaiError == 0 && mmdbError == MMDB_SUCCESS && result.found_entry) {
                info.asn = getUint32Value(result, "autonomous_system_number");
                info.organization = getUtf8Value(result, "autonomous_system_organization", nullptr);
            }
        }

        m_cache.emplace_front(ip, info);
        m_cacheIndex[ip] = m_cache.begin();
        if (m_cache.size() > m_cacheCapacity) {
            m_cacheIndex.erase(m_cache.back().first);
            m_cache.pop_back();
        }
        return info;
    }

    bool GeoIPResolver::isAvailable() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_database->countryOpen || m_database->asnOpen;
    }

    std::string GeoIPResolver::status() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_database->status;
    }

} // namespace core
