#include "core/ResourcePaths.hpp"

#include <array>
#include <cstdlib>
#include <string>
#include <system_error>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <shlobj.h>
#elif defined(__APPLE__)
#  include <mach-o/dyld.h>
#  include <vector>
#else
#  include <unistd.h>
#  include <limits.h>
#endif

namespace {
    // Reads an env var portably. On Windows, prefers _wgetenv so UTF-16 paths
    // (e.g. paths with non-ASCII usernames) survive. Returns an empty path
    // when unset; the caller decides how to fall back.
    std::filesystem::path getEnvPath(const char* name) {
#if defined(_WIN32)
        std::wstring wname(name, name + std::string(name).size());
        const wchar_t* value = _wgetenv(wname.c_str());
        return (value && *value) ? std::filesystem::path(value) : std::filesystem::path{};
#else
        const char* value = std::getenv(name);
        return (value && *value) ? std::filesystem::path(value) : std::filesystem::path{};
#endif
    }
}

namespace core {

    namespace {

        std::filesystem::path queryExecutablePath() {
            std::error_code ec;
#if defined(_WIN32)
            // MAX_PATH is a hint, not a hard limit on modern Windows; grow the
            // buffer on truncation so long install paths do not silently break.
            std::wstring buffer(MAX_PATH, L'\0');
            for (;;) {
                DWORD written = GetModuleFileNameW(nullptr, buffer.data(),
                    static_cast<DWORD>(buffer.size()));
                if (written == 0) {
                    return {};
                }
                if (written < buffer.size()) {
                    buffer.resize(written);
                    break;
                }
                buffer.resize(buffer.size() * 2);
            }
            std::filesystem::path result(buffer);
#elif defined(__APPLE__)
            uint32_t size = 0;
            _NSGetExecutablePath(nullptr, &size);
            std::vector<char> buffer(size);
            if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
                return {};
            }
            std::filesystem::path result(buffer.data());
#else
            // Prefer /proc/self/exe (Linux); readlink resolves symlinks so
            // launchers such as GNOME `.desktop` files still yield the real
            // binary path.
            std::string buffer(PATH_MAX, '\0');
            ssize_t len = ::readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
            if (len <= 0) {
                return {};
            }
            buffer.resize(static_cast<size_t>(len));
            std::filesystem::path result(buffer);
#endif
            auto canonical = std::filesystem::weakly_canonical(result, ec);
            if (ec) {
                return result;
            }
            return canonical;
        }

    } // namespace

    const std::filesystem::path& executablePath() {
        static const std::filesystem::path path = queryExecutablePath();
        return path;
    }

    std::filesystem::path executableDir() {
        const auto& exe = executablePath();
        return exe.empty() ? std::filesystem::path{} : exe.parent_path();
    }

    std::filesystem::path resource(const std::filesystem::path& relative) {
        const auto dir = executableDir();
        // Empty exe dir means the OS lookup failed. Fall back to the
        // process's CWD, which matches pre-refactor behavior on the platforms
        // where the query never actually fails in practice.
        if (dir.empty()) {
            return std::filesystem::current_path() / relative;
        }

        // Ordered candidates. The first existing path wins; if none exists
        // we return the release-ZIP layout so error messages point somewhere
        // sensible instead of a bogus CWD-relative path.
        std::array<std::filesystem::path, 4> candidates{
#if defined(__APPLE__)
            dir / ".." / "Resources" / relative,   // inside a .app bundle
#else
            std::filesystem::path{},               // placeholder, skipped below
#endif
            dir / relative,                        // release ZIP layout
            dir / ".." / relative,                 // dev: build/Release/NetProbe.exe → repo/data/...
            dir / ".." / ".." / relative,          // dev: some multi-config layouts
        };

        std::error_code ec;
        for (const auto& candidate : candidates) {
            if (candidate.empty()) {
                continue;
            }
            if (std::filesystem::exists(candidate, ec)) {
                return std::filesystem::weakly_canonical(candidate, ec);
            }
        }
        return dir / relative;
    }

    std::filesystem::path userDataDir() {
        // NETPROBE_DATA_DIR wins unconditionally. Useful for CI, portable
        // installs, and tests — the same knob users can flip if the default
        // location is wrong for their setup.
        if (auto override_ = getEnvPath("NETPROBE_DATA_DIR"); !override_.empty()) {
            return override_;
        }

#if defined(_WIN32)
        // %LOCALAPPDATA%\NetProbe. Wide-char API so non-ASCII usernames
        // (Cyrillic, CJK, etc.) survive without codepage corruption.
        wchar_t* raw = nullptr;
        std::filesystem::path base;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw))
            && raw != nullptr) {
            base = std::filesystem::path(raw);
            CoTaskMemFree(raw);
        }
        if (base.empty()) {
            base = getEnvPath("LOCALAPPDATA");
        }
        if (!base.empty()) {
            return base / "NetProbe";
        }
#elif defined(__APPLE__)
        // ~/Library/Application Support/NetProbe. Standard Apple location
        // for per-user data; survives app moves and Gatekeeper translocation.
        if (auto home = getEnvPath("HOME"); !home.empty()) {
            return home / "Library" / "Application Support" / "NetProbe";
        }
#else
        // XDG Base Directory. $XDG_DATA_HOME wins if set, otherwise the
        // spec's default of $HOME/.local/share.
        if (auto xdg = getEnvPath("XDG_DATA_HOME"); !xdg.empty()) {
            return xdg / "netprobe";
        }
        if (auto home = getEnvPath("HOME"); !home.empty()) {
            return home / ".local" / "share" / "netprobe";
        }
#endif
        // Last-resort fallback so callers always get a printable path.
        return std::filesystem::current_path() / "netprobe-data";
    }

}
