#pragma once

#include <filesystem>

namespace core {

    // Path helpers for two distinct kinds of files:
    //
    //   1. Immutable resources shipped WITH the app (e.g. data/sample.pcap).
    //      Use `resource()`. Search order resolves against the running
    //      executable, so files are found whether launched from a shell,
    //      double-clicked in Explorer, or run from a macOS .app bundle
    //      where cwd is `/`.
    //
    //   2. User-provided or user-modifiable data (e.g. GeoLite2 .mmdb
    //      databases the user downloaded themselves). Use `userDataDir()`.
    //      Points at a stable per-user location outside the install:
    //         macOS:   $HOME/Library/Application Support/NetProbe
    //         Windows: %LOCALAPPDATA%/NetProbe
    //         Linux:   $XDG_DATA_HOME/netprobe  (fallback: $HOME/.local/share/netprobe)
    //      Overridable by setting the NETPROBE_DATA_DIR environment variable,
    //      which is useful for CI, packaging tests, and portable installs.
    //
    // Mixing the two would be a bug: writing user files into the .app bundle
    // invalidates a code signature on macOS, and reading from inside the
    // bundle for user data is not what users expect.

    // Absolute path to the running executable, or an empty path if the OS
    // lookup fails. Cached after first call.
    const std::filesystem::path& executablePath();

    // Directory containing the running executable.
    std::filesystem::path executableDir();

    // Resolve an immutable resource file (or directory) shipped alongside the
    // executable. `relative` is interpreted relative to the install root,
    // e.g. "data/sample.pcap" or "data".
    //
    // Search order:
    //   1. macOS only: <exe>/../Resources/<relative>       (inside .app)
    //   2. <exe>/<relative>                                 (release ZIP)
    //   3. <exe>/../<relative>                              (dev: build/Release/NetProbe.exe → repo/data/...)
    //   4. <exe>/../../<relative>                           (dev: multi-config generators)
    // Returns the first that exists. If none does, returns the exe-adjacent
    // candidate so error messages point somewhere sensible.
    std::filesystem::path resource(const std::filesystem::path& relative);

    // Per-user data directory. Does not create the directory; callers decide
    // whether to create-on-demand (typical for writable state) or just probe
    // (typical for optional user-provided files like GeoLite2 databases).
    //
    // Never returns an empty path — falls back to the current working
    // directory if every OS query fails, so callers can always print
    // something useful. NETPROBE_DATA_DIR, if set, wins unconditionally.
    std::filesystem::path userDataDir();

}
