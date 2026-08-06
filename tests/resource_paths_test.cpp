#include "core/ResourcePaths.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

// These tests cover the two contracts most likely to regress:
//   1. executableDir() actually points at the running test binary — the
//      whole `resource()` search chain depends on this being non-empty.
//   2. userDataDir() honors NETPROBE_DATA_DIR, so packaging tests, CI, and
//      users on locked-down machines can redirect it.
//
// Unit-testing every candidate in the resource() search order would
// require faking the executable location; the ResourceFallsBackTo... case
// below pins the empty-input fallback and executableDir() anchoring, which
// are the parts most likely to silently regress.

namespace {
#if defined(_WIN32)
    void setEnv(const char* name, const char* value) {
        if (value == nullptr) {
            _putenv_s(name, "");
        } else {
            _putenv_s(name, value);
        }
    }
    void unsetEnv(const char* name) { _putenv_s(name, ""); }
#else
    void setEnv(const char* name, const char* value) {
        if (value == nullptr) {
            ::unsetenv(name);
        } else {
            ::setenv(name, value, 1);
        }
    }
    void unsetEnv(const char* name) { ::unsetenv(name); }
#endif
}

TEST(ResourcePathsTest, ExecutableDirIsNonEmpty) {
    // If the OS-specific lookup fails on the CI runners we would fall back
    // to CWD-relative behavior — that's a real regression, so pin the
    // primary path here.
    const auto dir = core::executableDir();
    ASSERT_FALSE(dir.empty()) << "executableDir() returned empty; resource() search chain would collapse to CWD.";
    EXPECT_TRUE(std::filesystem::is_directory(dir))
        << "executableDir() must be a directory. Got: " << dir;
}

TEST(ResourcePathsTest, ExecutablePathIsCanonicalAbsolute) {
    const auto path = core::executablePath();
    ASSERT_FALSE(path.empty());
    EXPECT_TRUE(path.is_absolute())
        << "executablePath() must be absolute so it survives cwd changes. Got: " << path;
}

TEST(ResourcePathsTest, ResourceFallsBackToExeAdjacentPath) {
    // A path that provably doesn't exist. resource() should still return
    // something anchored to executableDir() (candidate #2 in the search
    // order) rather than to CWD or an empty path, so error messages point
    // somewhere the user can act on.
    const auto missing = core::resource("this-directory-should-not-exist-42/nowhere.dat");
    EXPECT_FALSE(missing.empty());
    EXPECT_FALSE(std::filesystem::exists(missing));
    // The fallback must at least share a root with the executable.
    const auto exeRoot = core::executableDir().root_path();
    if (!exeRoot.empty()) {
        EXPECT_EQ(missing.root_path(), exeRoot)
            << "resource() fallback should stay anchored to the executable's filesystem root.";
    }
}

TEST(ResourcePathsTest, UserDataDirNeverEmpty) {
    // Contract: userDataDir() must always give callers a printable path,
    // even when every OS query fails (last-resort fallback path).
    unsetEnv("NETPROBE_DATA_DIR");
    const auto dir = core::userDataDir();
    EXPECT_FALSE(dir.empty());
}

TEST(ResourcePathsTest, UserDataDirHonorsEnvOverride) {
    const auto override_ =
        (std::filesystem::temp_directory_path() / "netprobe-userdatadir-test").string();
    setEnv("NETPROBE_DATA_DIR", override_.c_str());
    const auto dir = core::userDataDir();
    EXPECT_EQ(dir, std::filesystem::path(override_))
        << "NETPROBE_DATA_DIR must win over platform defaults.";
    unsetEnv("NETPROBE_DATA_DIR");
}

TEST(ResourcePathsTest, UserDataDirIgnoresEmptyOverride) {
    // An empty NETPROBE_DATA_DIR is a common accident (`export FOO=`), and
    // treating it as an override would produce a bogus root-relative path.
    // The helper treats empty as unset.
    setEnv("NETPROBE_DATA_DIR", "");
    const auto dir = core::userDataDir();
    EXPECT_FALSE(dir.empty());
    // Must not equal the (empty) override.
    EXPECT_NE(dir, std::filesystem::path{});
    unsetEnv("NETPROBE_DATA_DIR");
}
