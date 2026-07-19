// NetProbe headless CLI.
//
// Runs the same capture and analysis pipeline as the GUI with no window, so
// captures can be taken and flows exported over SSH, in CI, or on a server.
// Deliberately small: replay a file or capture for a bounded time, then write
// the flow table as JSON or CSV.

#include "capture/CaptureEngine.hpp"
#include "core/AnalysisSession.hpp"
#include "core/FlowExporter.hpp"
#include "core/PacketQueue.hpp"

#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifndef NETPROBE_VERSION
#define NETPROBE_VERSION "unknown"
#endif

namespace {

    // Exit codes are part of the CLI's contract with scripts that call it.
    constexpr int kExitSuccess = 0;
    constexpr int kExitUsage = 1;
    constexpr int kExitRuntime = 2;

    // Set from the signal handler; only ever transitions false -> true.
    std::atomic<bool> g_stopRequested{false};

    extern "C" void handleInterrupt(int) {
        g_stopRequested.store(true, std::memory_order_release);
    }

    enum class OutputFormat { Json, Csv };

    struct Options {
        bool listDevices = false;
        bool showHelp = false;
        bool showVersion = false;
        std::string readPath;    // offline capture to replay
        std::string device;      // live adapter to capture from
        std::string bpfFilter;
        std::string outputPath;  // "-" means stdout
        std::optional<OutputFormat> format;
        std::optional<int> durationSeconds;
        std::optional<uint64_t> packetLimit;
        bool resolveProcesses = true;
    };

    void printUsage(std::ostream& out) {
        out << "NetProbe CLI " NETPROBE_VERSION " - headless packet capture and flow export\n"
               "\n"
               "Usage:\n"
               "  netprobe-cli --list-devices\n"
               "  netprobe-cli -r <capture.pcap> -o <flows.json>\n"
               "  netprobe-cli -i <device> [-f <bpf>] [--duration <sec>] -o <flows.json>\n"
               "\n"
               "Source (exactly one required):\n"
               "  -r, --read <file>       Replay an offline capture file\n"
               "  -i, --device <name>     Capture live from an adapter (needs privileges)\n"
               "\n"
               "Output:\n"
               "  -o, --output <path>     Destination file, or '-' for stdout\n"
               "      --format <json|csv> Override the format inferred from the extension\n"
               "\n"
               "Capture limits (live capture only):\n"
               "      --duration <sec>    Stop after this many seconds\n"
               "      --packet-count <n>  Stop after this many packets\n"
               "\n"
               "Other:\n"
               "      --no-process        Skip owning-process lookup\n"
               "      --list-devices      List capture adapters and exit\n"
               "  -h, --help              Show this help and exit\n"
               "  -V, --version           Show the version and exit\n"
               "\n"
               "Interrupting with Ctrl+C stops the capture and still writes the output.\n";
    }

    // Returns false when `text` is not a complete non-negative integer.
    template <typename T>
    bool parseNonNegative(std::string_view text, T& value) {
        if (text.empty()) return false;
        const char* begin = text.data();
        const char* end = begin + text.size();
        const auto result = std::from_chars(begin, end, value);
        return result.ec == std::errc{} && result.ptr == end;
    }

    bool endsWith(const std::string& value, std::string_view suffix) {
        return value.size() >= suffix.size()
            && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    // Parses argv. On failure prints the reason to stderr and returns nullopt.
    std::optional<Options> parseArguments(int argc, char** argv) {
        Options options;

        // Every option below takes exactly one value; centralising the
        // "is there a next argument" check keeps the loop readable.
        const auto takeValue = [&](int& index, std::string_view flag) -> const char* {
            if (index + 1 >= argc) {
                std::cerr << "netprobe-cli: " << flag << " requires a value\n";
                return nullptr;
            }
            return argv[++index];
        };

        for (int i = 1; i < argc; ++i) {
            const std::string_view argument = argv[i];

            if (argument == "-h" || argument == "--help") {
                options.showHelp = true;
                return options;
            }
            if (argument == "-V" || argument == "--version") {
                options.showVersion = true;
                return options;
            }
            if (argument == "--list-devices") {
                options.listDevices = true;
                continue;
            }
            if (argument == "--no-process") {
                options.resolveProcesses = false;
                continue;
            }
            if (argument == "-r" || argument == "--read") {
                const char* value = takeValue(i, argument);
                if (!value) return std::nullopt;
                options.readPath = value;
                continue;
            }
            if (argument == "-i" || argument == "--device") {
                const char* value = takeValue(i, argument);
                if (!value) return std::nullopt;
                options.device = value;
                continue;
            }
            if (argument == "-f" || argument == "--filter") {
                const char* value = takeValue(i, argument);
                if (!value) return std::nullopt;
                options.bpfFilter = value;
                continue;
            }
            if (argument == "-o" || argument == "--output") {
                const char* value = takeValue(i, argument);
                if (!value) return std::nullopt;
                options.outputPath = value;
                continue;
            }
            if (argument == "--format") {
                const char* value = takeValue(i, argument);
                if (!value) return std::nullopt;
                const std::string_view format = value;
                if (format == "json")      options.format = OutputFormat::Json;
                else if (format == "csv")  options.format = OutputFormat::Csv;
                else {
                    std::cerr << "netprobe-cli: unknown format '" << format
                              << "' (expected 'json' or 'csv')\n";
                    return std::nullopt;
                }
                continue;
            }
            if (argument == "--duration") {
                const char* value = takeValue(i, argument);
                if (!value) return std::nullopt;
                int seconds = 0;
                if (!parseNonNegative(value, seconds) || seconds <= 0) {
                    std::cerr << "netprobe-cli: --duration expects a positive number of seconds\n";
                    return std::nullopt;
                }
                options.durationSeconds = seconds;
                continue;
            }
            if (argument == "--packet-count") {
                const char* value = takeValue(i, argument);
                if (!value) return std::nullopt;
                uint64_t count = 0;
                if (!parseNonNegative(value, count) || count == 0) {
                    std::cerr << "netprobe-cli: --packet-count expects a positive number\n";
                    return std::nullopt;
                }
                options.packetLimit = count;
                continue;
            }

            std::cerr << "netprobe-cli: unrecognized option '" << argument << "'\n";
            return std::nullopt;
        }

        return options;
    }

    // Validates the combination of options, not just their individual syntax.
    bool validate(const Options& options) {
        if (options.listDevices) return true;

        const bool hasFile = !options.readPath.empty();
        const bool hasDevice = !options.device.empty();

        if (!hasFile && !hasDevice) {
            std::cerr << "netprobe-cli: nothing to do - pass --read <file> or --device <name>\n"
                         "Try 'netprobe-cli --help'.\n";
            return false;
        }
        if (hasFile && hasDevice) {
            std::cerr << "netprobe-cli: --read and --device are mutually exclusive\n";
            return false;
        }
        if (options.outputPath.empty()) {
            std::cerr << "netprobe-cli: no destination - pass --output <path> (or '-' for stdout)\n";
            return false;
        }
        // Silently ignoring a flag that cannot apply is how people end up
        // trusting a limit that was never enforced.
        if (hasFile && (options.durationSeconds || options.packetLimit)) {
            std::cerr << "netprobe-cli: --duration and --packet-count apply to live capture only\n";
            return false;
        }
        if (hasFile && !options.bpfFilter.empty()) {
            std::cerr << "netprobe-cli: --filter applies to live capture only\n";
            return false;
        }
        return true;
    }

    OutputFormat resolveFormat(const Options& options) {
        if (options.format) return *options.format;
        if (endsWith(options.outputPath, ".csv")) return OutputFormat::Csv;
        return OutputFormat::Json;
    }

    int64_t currentUnixTimeMicroseconds() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    int listDevices(const capture::CaptureEngine& engine) {
        const auto devices = engine.getAvailableDevices();
        if (devices.empty()) {
            std::cerr << "No capture devices found. On most systems live capture needs "
                         "administrator or root privileges.\n";
            return kExitRuntime;
        }
        for (const auto& device : devices) {
            std::cout << device.name;
            if (!device.description.empty()) std::cout << "  (" << device.description << ")";
            std::cout << '\n';
        }
        return kExitSuccess;
    }

    // Replays a capture file. Packets are handed over as they are read, so a
    // file of any size is processed without loss.
    bool runOffline(capture::CaptureEngine& engine, core::AnalysisSession& session,
        const Options& options, uint64_t& packetsAnalyzed) {
        std::string error;
        const bool ok = engine.replayFile(options.readPath,
            [&](const core::PacketData& packet) {
                session.feed(packet);
                ++packetsAnalyzed;
            }, error);

        if (!ok) {
            std::cerr << "netprobe-cli: unable to read '" << options.readPath << "': "
                      << error << '\n';
            return false;
        }
        return true;
    }

    // Captures live until the duration elapses, the packet limit is reached,
    // or the user interrupts.
    bool runLive(capture::CaptureEngine& engine, core::PacketQueue& queue,
        core::AnalysisSession& session, const Options& options, uint64_t& packetsAnalyzed) {
        engine.startCapture(options.device);
        if (!engine.isCapturing()) {
            std::cerr << "netprobe-cli: unable to open device '" << options.device
                      << "'. Live capture usually requires administrator or root privileges.\n"
                         "Run --list-devices to see the available adapters.\n";
            return false;
        }

        if (!options.bpfFilter.empty()) {
            std::string error;
            if (!engine.setFilter(options.bpfFilter, error)) {
                std::cerr << "netprobe-cli: invalid capture filter '" << options.bpfFilter
                          << "': " << error << '\n';
                engine.stopCapture();
                return false;
            }
        }

        const auto deadline = options.durationSeconds
            ? std::optional{std::chrono::steady_clock::now()
                + std::chrono::seconds(*options.durationSeconds)}
            : std::nullopt;

        std::cerr << "Capturing on " << options.device;
        if (options.durationSeconds) std::cerr << " for " << *options.durationSeconds << "s";
        if (options.packetLimit) std::cerr << ", up to " << *options.packetLimit << " packets";
        std::cerr << ". Press Ctrl+C to stop early.\n";

        while (!g_stopRequested.load(std::memory_order_acquire)) {
            if (deadline && std::chrono::steady_clock::now() >= *deadline) break;
            if (options.packetLimit && packetsAnalyzed >= *options.packetLimit) break;

            auto packet = queue.try_pop();
            if (!packet) {
                // Nothing buffered: yield briefly rather than spin a core.
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }
            session.feed(*packet);
            ++packetsAnalyzed;
        }

        engine.stopCapture();

        // The capture thread has stopped, but packets it already queued are
        // still pending; analysing them costs nothing and makes the totals
        // match what was actually captured.
        while (auto packet = queue.try_pop()) {
            if (options.packetLimit && packetsAnalyzed >= *options.packetLimit) break;
            session.feed(*packet);
            ++packetsAnalyzed;
        }

        if (const size_t dropped = queue.droppedPackets(); dropped > 0) {
            std::cerr << "Warning: " << dropped << " packets were dropped because analysis "
                         "could not keep up with the capture; flow totals undercount by that much.\n";
        }
        return true;
    }

    bool writeOutput(const std::vector<core::Flow>& flows, const Options& options,
        OutputFormat format) {
        if (options.outputPath == "-") {
            if (format == OutputFormat::Csv) core::FlowExporter::writeCsv(flows, std::cout);
            else                             core::FlowExporter::writeJson(flows, std::cout);
            std::cout.flush();
            if (!std::cout.good()) {
                std::cerr << "netprobe-cli: writing to stdout failed\n";
                return false;
            }
            return true;
        }

        std::string error;
        const bool ok = format == OutputFormat::Csv
            ? core::FlowExporter::writeCsv(flows, options.outputPath, error)
            : core::FlowExporter::writeJson(flows, options.outputPath, error);
        if (!ok) {
            std::cerr << "netprobe-cli: unable to write '" << options.outputPath << "': "
                      << error << '\n';
            return false;
        }
        return true;
    }

} // namespace

static int run(int argc, char** argv) {
    const auto parsed = parseArguments(argc, argv);
    if (!parsed) {
        std::cerr << "Try 'netprobe-cli --help'.\n";
        return kExitUsage;
    }
    const Options& options = *parsed;

    if (options.showHelp) {
        printUsage(std::cout);
        return kExitSuccess;
    }
    if (options.showVersion) {
        std::cout << "netprobe-cli " NETPROBE_VERSION "\n";
        return kExitSuccess;
    }
    if (!validate(options)) return kExitUsage;

    core::PacketQueue queue;
    capture::CaptureEngine engine(queue);

    if (options.listDevices) return listDevices(engine);

    std::signal(SIGINT, handleInterrupt);
#ifdef SIGTERM
    std::signal(SIGTERM, handleInterrupt);
#endif

    // Replaying a file means the sockets that owned those packets are long
    // gone, so the socket-table walk is pure overhead with nothing to find.
    const bool resolveProcesses = options.resolveProcesses && options.readPath.empty();
    core::AnalysisSession session(resolveProcesses);

    uint64_t packetsAnalyzed = 0;
    const bool captured = options.readPath.empty()
        ? runLive(engine, queue, session, options, packetsAnalyzed)
        : runOffline(engine, session, options, packetsAnalyzed);
    if (!captured) return kExitRuntime;

    const auto flows = session.flows(currentUnixTimeMicroseconds());
    const OutputFormat format = resolveFormat(options);
    if (!writeOutput(flows, options, format)) return kExitRuntime;

    std::cerr << "Analyzed " << packetsAnalyzed << " packets into " << flows.size()
              << " flows; wrote "
              << (options.outputPath == "-" ? std::string{"stdout"} : options.outputPath)
              << " as " << (format == OutputFormat::Csv ? "CSV" : "JSON") << ".\n";
    return kExitSuccess;
}

int main(int argc, char** argv) {
    // An exception escaping main terminates with no diagnostic at all, which
    // for a tool run from a script means a bare failure code and no clue why.
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        // Reported without iostreams deliberately: a handler that can itself
        // throw would let the exception escape after all, which is the whole
        // thing this is here to prevent. std::fputs does not throw.
        std::fputs("netprobe-cli: unexpected failure: ", stderr);
        std::fputs(error.what(), stderr);
        std::fputs("\n", stderr);
        return kExitRuntime;
    } catch (...) {
        std::fputs("netprobe-cli: unexpected failure\n", stderr);
        return kExitRuntime;
    }
}
