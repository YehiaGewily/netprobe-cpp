#pragma once

#include "core/FlowAggregator.hpp"
#include "core/GeoIPResolver.hpp"

#include <iosfwd>
#include <string>
#include <vector>

namespace core {

    // Serializes a flow snapshot for consumption outside NetProbe: a
    // spreadsheet (CSV) or a pipeline such as Elastic, Splunk, or jq (JSON).
    //
    // `geo` is optional. When null — or when no GeoLite2 database is
    // installed — the country and organization fields are written empty,
    // which is the honest representation of "not known" rather than a
    // structural difference in the output.
    class FlowExporter {
    public:
        static void writeCsv(const std::vector<Flow>& flows, std::ostream& out,
            GeoIPResolver* geo = nullptr);
        static void writeJson(const std::vector<Flow>& flows, std::ostream& out,
            GeoIPResolver* geo = nullptr);

        // File variants. Return false and set `error` when the destination
        // cannot be opened or the write fails part way through.
        static bool writeCsv(const std::vector<Flow>& flows, const std::string& path,
            std::string& error, GeoIPResolver* geo = nullptr);
        static bool writeJson(const std::vector<Flow>& flows, const std::string& path,
            std::string& error, GeoIPResolver* geo = nullptr);

        // Exposed for testing: appends `value` to `out` as a quoted JSON
        // string. Hostnames and SNI arrive as raw bytes off the wire and are
        // not guaranteed to be valid UTF-8, so anything malformed is replaced
        // with U+FFFD rather than emitted verbatim into the document.
        static void appendJsonString(std::string& out, const std::string& value);
    };

} // namespace core
