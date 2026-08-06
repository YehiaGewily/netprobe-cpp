#include "core/GeoIPResolver.hpp"

#include "core/ResourcePaths.hpp"

#include <filesystem>
#include <string>
#include <maxminddb.h>

namespace core {

    std::string organizationLabel(const GeoIPInfo& info) {
        if (info.organization.empty()) return std::string{"-"};
        return info.asn == 0
            ? info.organization
            : ("AS" + std::to_string(info.asn) + " " + info.organization);
    }

    namespace {
        std::filesystem::path geoIpDataDirectory() {
            // GeoLite2 databases are user-provided (MaxMind account required),
            // not shipped with the app. They live in the per-user data
            // directory rather than alongside the executable — writing files
            // inside a signed macOS .app invalidates its signature, and users
            // reasonably expect their data outside install locations.
            //
            // Override via NETPROBE_DATA_DIR (see core::userDataDir).
            return userDataDir();
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

        Database(const std::filesystem::path& countryPath, const std::filesystem::path& asnPath, const std::string& customStatusSuffix = "") {
            countryOpen = MMDB_open(countryPath.string().c_str(), MMDB_MODE_MMAP, &country) == MMDB_SUCCESS;
            asnOpen = MMDB_open(asnPath.string().c_str(), MMDB_MODE_MMAP, &asn) == MMDB_SUCCESS;
            if (countryOpen || asnOpen) {
                status = "GeoLite2 enrichment enabled." + customStatusSuffix;
            } else {
                // Point users at ONE canonical location — the parent of
                // whichever path we tried — instead of dumping two long
                // strings. `countryPath` and `asnPath` share a directory.
                status = "GeoLite2 databases not found. Place GeoLite2-Country.mmdb and "
                    "GeoLite2-ASN.mmdb in " + countryPath.parent_path().string()
                    + " (override with the NETPROBE_DATA_DIR environment variable).";
            }
        }

        ~Database() {
            if (countryOpen) MMDB_close(&country);
            if (asnOpen) MMDB_close(&asn);
        }
    };

    GeoIPResolver::GeoIPResolver(size_t cacheCapacity)
        : m_cacheCapacity(cacheCapacity > 0 ? cacheCapacity : 1) {
        const auto newDir = userDataDir();
        const auto primaryCountry = newDir / "GeoLite2-Country.mmdb";
        const auto primaryAsn = newDir / "GeoLite2-ASN.mmdb";

        std::error_code ec;
        const bool primaryExists = std::filesystem::exists(primaryCountry, ec) || std::filesystem::exists(primaryAsn, ec);

        if (primaryExists) {
            m_database = std::make_unique<Database>(primaryCountry, primaryAsn);
            if (m_database->countryOpen || m_database->asnOpen) {
                return;
            }
        }

        // Legacy location fallback (data/ directory relative to resource path)
        const auto legacyCountry = resource("data/GeoLite2-Country.mmdb");
        const auto legacyAsn = resource("data/GeoLite2-ASN.mmdb");
        const bool legacyExists = std::filesystem::exists(legacyCountry, ec) || std::filesystem::exists(legacyAsn, ec);

        if (legacyExists) {
            const std::string migrationMsg = " (found in old location; move to " + newDir.string() + " to persist across upgrades).";
            auto legacyDb = std::make_unique<Database>(legacyCountry, legacyAsn, migrationMsg);
            if (legacyDb->countryOpen || legacyDb->asnOpen) {
                m_database = std::move(legacyDb);
                return;
            }
        }

        // Default back to primary location if legacy files were missing or failed to open
        m_database = std::make_unique<Database>(primaryCountry, primaryAsn);
    }

    GeoIPResolver::GeoIPResolver(const std::filesystem::path& countryDatabasePath,
        const std::filesystem::path& asnDatabasePath, size_t cacheCapacity)
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
