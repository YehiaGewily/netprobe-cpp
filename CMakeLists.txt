cmake_minimum_required(VERSION 3.20)
project(NetProbe VERSION 1.2.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)

# Emit compile_commands.json for clang-tidy and editor tooling. Note that the
# Visual Studio generator ignores this; use Ninja when you need the database
# (see the clang-tidy CI job).
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# AddressSanitizer + UndefinedBehaviorSanitizer for local debug runs and CI.
# Clang/GCC only; MSVC ASan has compatibility caveats with the third-party
# CMake projects we pull in, so we restrict this to non-MSVC compilers.
option(ENABLE_SANITIZERS "Build with -fsanitize=address,undefined (Clang/GCC)" OFF)
if(ENABLE_SANITIZERS AND NOT MSVC)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# --- 1. Platform Capture Configuration ---
if(WIN32)
    set(NPCAP_SDK_PATH "C:/Npcap-SDK" CACHE PATH "Path to the Npcap SDK root")
    set(PCAP_INCLUDE_DIR "${NPCAP_SDK_PATH}/Include")
    set(NPCAP_LIB_DIR "${NPCAP_SDK_PATH}/Lib/x64")
    set(PCAP_LIBRARIES "${NPCAP_LIB_DIR}/wpcap.lib" "${NPCAP_LIB_DIR}/Packet.lib")

    if(NOT EXISTS "${PCAP_INCLUDE_DIR}/pcap.h")
        message(FATAL_ERROR "Npcap SDK was not found at ${NPCAP_SDK_PATH}. Install the SDK or set NPCAP_SDK_PATH.")
    endif()

    # Split by consumer: CORE libraries back the capture/analysis library (and
    # therefore also the tests and the headless CLI), while GUI libraries are
    # needed only by the windowed executable.
    set(NETPROBE_CORE_PLATFORM_LIBRARIES ws2_32 iphlpapi)
    set(NETPROBE_GUI_PLATFORM_LIBRARIES dwmapi opengl32)
else()
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h pcap/pcap.h REQUIRED)
    find_library(PCAP_LIBRARY NAMES pcap REQUIRED)
    find_package(OpenGL REQUIRED)

    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    set(NETPROBE_CORE_PLATFORM_LIBRARIES)
    set(NETPROBE_GUI_PLATFORM_LIBRARIES OpenGL::GL)
endif()

# --- 2. FetchContent Dependencies (Gui Stack) ---
include(FetchContent)

# GLFW
message(STATUS "Fetching GLFW...")
set(GLFW_INSTALL OFF CACHE BOOL "Disable GLFW installation from NetProbe packages" FORCE)
FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw
    GIT_TAG        3.4
)
FetchContent_MakeAvailable(glfw)

# Dear ImGui
message(STATUS "Fetching Dear ImGui...")
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui
    # Pinned docking revision: avoids API changes from the moving branch.
    GIT_TAG        036bf939b6f8d74ad76bcf926b757c56e68c54ff
)
FetchContent_MakeAvailable(imgui)

# ImPlot
message(STATUS "Fetching ImPlot...")
FetchContent_Declare(
    implot
    GIT_REPOSITORY https://github.com/epezent/implot
    # Pinned revision compatible with the Dear ImGui revision above.
    GIT_TAG        d65a2bef53d32502407de3a4be80f191e2f412d7
)
FetchContent_MakeAvailable(implot)

# Native file picker for loading offline captures.
message(STATUS "Fetching Native File Dialog Extended...")
set(NFD_INSTALL OFF CACHE BOOL "Disable NFD installation from NetProbe packages" FORCE)
FetchContent_Declare(
    nfd
    GIT_REPOSITORY https://github.com/btzy/nativefiledialog-extended.git
    GIT_TAG        v1.2.1
)
FetchContent_MakeAvailable(nfd)

# Mbed TLS provides the crypto primitives used by the QUIC parser
# (HKDF-SHA256, AES-128-ECB, AES-128-GCM) to decrypt QUIC Initial packets and
# extract the inner TLS 1.3 ClientHello SNI.
message(STATUS "Fetching Mbed TLS...")
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
# Keep Mbed TLS's ~114 SDK headers out of `cmake --install`. Its static-lib
# install(TARGETS) rules have no off switch at all; those are kept out of the
# release ZIP by the component-scoped CPack setup in section 7 below.
set(INSTALL_MBEDTLS_HEADERS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.2
)
FetchContent_MakeAvailable(mbedtls)

# Local MaxMind DB reader used for optional GeoLite2 Country/ASN enrichment.
message(STATUS "Fetching libmaxminddb...")
FetchContent_Declare(
    libmaxminddb
    GIT_REPOSITORY https://github.com/maxmind/libmaxminddb.git
    GIT_TAG        1.12.2
)
# libmaxminddb uses the generic BUILD_TESTING option. Keep its internal test
# programs out of NetProbe's build while retaining this project's CTest suite.
set(_netprobe_build_testing ${BUILD_TESTING})
set(BUILD_TESTING OFF)
set(MAXMINDDB_BUILD_BINARIES OFF)
set(MAXMINDDB_INSTALL OFF)
FetchContent_MakeAvailable(libmaxminddb)
set(BUILD_TESTING ${_netprobe_build_testing})

if(BUILD_TESTING)
    set(INSTALL_GTEST OFF CACHE BOOL "Disable GoogleTest installation from NetProbe packages" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "Use the shared MSVC CRT for GoogleTest" FORCE)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.2
    )
    FetchContent_MakeAvailable(googletest)
endif()

# --- 3. Source Management ---
# Sources are listed explicitly rather than globbed: NetProbeTests and the
# fuzz harnesses select subsets of these files, and a glob silently changing
# what lands in which target is exactly the kind of surprise that costs an
# afternoon. Headers are listed too so they appear in IDE project trees.
set(NETPROBE_CORE_SOURCES
    src/capture/CaptureEngine.cpp
    src/capture/LibpcapBackend.cpp
    src/capture/NpcapBackend.cpp
    src/core/AnalysisSession.cpp
    src/core/DNSParser.cpp
    src/core/FlowAggregator.cpp
    src/core/FlowExporter.cpp
    src/core/GeoIPResolver.cpp
    src/core/ProcessResolver.cpp
    src/core/ProtocolParser.cpp
    src/core/QuicParser.cpp
    src/core/QuicTracker.cpp
    src/core/TlsReassembler.cpp

    src/capture/CaptureEngine.hpp
    src/capture/ICaptureBackend.hpp
    src/capture/PcapPlatform.hpp
    src/core/AnalysisSession.hpp
    src/core/DNSParser.hpp
    src/core/FlowAggregator.hpp
    src/core/FlowExporter.hpp
    src/core/GeoIPResolver.hpp
    src/core/HostnameCache.hpp
    src/core/LinkType.hpp
    src/core/NetworkPlatform.hpp
    src/core/PacketData.hpp
    src/core/PacketQueue.hpp
    src/core/ParsedPacket.hpp
    src/core/ProcessResolver.hpp
    src/core/ProtocolHeaders.hpp
    src/core/ProtocolParser.hpp
    src/core/QuicParser.hpp
    src/core/QuicTracker.hpp
    src/core/TlsReassembler.hpp
)

set(NETPROBE_GUI_SOURCES
    src/main.cpp
    src/ui/Dashboard.cpp
    src/ui/FlowsView.cpp
    src/ui/GuiLayer.cpp
    src/ui/PacketDetail.cpp
    src/ui/PacketView.cpp
    src/ui/StatsView.cpp

    src/ui/EmbeddedIcon.hpp
    src/ui/GuiLayer.hpp
    src/ui/GuiTheme.hpp
)

# ImGui Backend Wrapper
# We need to build the ImGui backends (GLFW + OpenGL3)
set(IMGUI_BACKEND_SOURCES
    "${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp"
)

# ImGui Core Sources (Required for linking)
set(IMGUI_CORE_SOURCES
    "${imgui_SOURCE_DIR}/imgui.cpp"
    "${imgui_SOURCE_DIR}/imgui_demo.cpp"
    "${imgui_SOURCE_DIR}/imgui_draw.cpp"
    "${imgui_SOURCE_DIR}/imgui_tables.cpp"
    "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
)

# ImPlot Core Sources
set(IMPLOT_SOURCES
    "${implot_SOURCE_DIR}/implot.cpp"
    "${implot_SOURCE_DIR}/implot_items.cpp"
    "${implot_SOURCE_DIR}/implot_demo.cpp"
)

# --- 4. Core Library ---
# Capture + parsing + analysis, with no dependency on ImGui/GLFW. The GUI, the
# headless CLI, and the test suite all build on this.
add_library(NetProbeCore STATIC ${NETPROBE_CORE_SOURCES})

target_include_directories(NetProbeCore PUBLIC
    include
    src
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(NetProbeCore PUBLIC
    maxminddb::maxminddb
    MbedTLS::mbedcrypto
    ${PCAP_LIBRARIES}
    ${NETPROBE_CORE_PLATFORM_LIBRARIES}
)

# PRIVATE: these configure how core's own sources compile; consumers neither
# need nor should inherit them.
target_compile_definitions(NetProbeCore PRIVATE
    NETPROBE_GEOIP_DATA_DIR="${CMAKE_SOURCE_DIR}/data"
    NETPROBE_VERSION="${PROJECT_VERSION}"
)

# --- 4b. GUI Executable Target ---
add_executable(NetProbe
    ${NETPROBE_GUI_SOURCES}
    ${IMGUI_BACKEND_SOURCES}
    ${IMGUI_CORE_SOURCES}
    ${IMPLOT_SOURCES}
)

# Embed a Windows .ico into NetProbe.exe when one is present. The build stays
# fully optional — if resources/netprobe.ico doesn't exist the .rc file isn't
# compiled and the binary keeps its default icon.
if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/resources/netprobe.ico")
    target_sources(NetProbe PRIVATE resources/netprobe.rc)
    message(STATUS "Embedding resources/netprobe.ico into NetProbe.exe")
endif()

# --- 5. Include Directories ---
# src/include/pcap come through NetProbeCore's PUBLIC includes.
target_include_directories(NetProbe PRIVATE
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
    ${implot_SOURCE_DIR}
)

# --- 6. Linking ---
target_link_libraries(NetProbe PRIVATE
    NetProbeCore
    glfw
    nfd::nfd
    ${NETPROBE_GUI_PLATFORM_LIBRARIES}
)
target_compile_definitions(NetProbe PRIVATE
    NETPROBE_VERSION="${PROJECT_VERSION}"
)

# --- 6b. Headless CLI ---
# Links NetProbeCore only: no ImGui, GLFW, or OpenGL, so it builds and runs on
# a machine with no display.
add_executable(NetProbeCli src/cli/main.cpp)
target_link_libraries(NetProbeCli PRIVATE NetProbeCore)
target_compile_definitions(NetProbeCli PRIVATE
    NETPROBE_VERSION="${PROJECT_VERSION}"
)
set_target_properties(NetProbeCli PROPERTIES OUTPUT_NAME "netprobe-cli")

# Everything NetProbe ships lives in the "runtime" component, and CPack is told
# to package only that component. FetchContent dependencies contribute install
# rules that cannot all be disabled (Mbed TLS installs its static libs
# unconditionally); they land in other components and never reach the ZIP.
# COMPONENT binds to the preceding artifact-kind block, so it must be
# repeated for RUNTIME and BUNDLE separately.
install(TARGETS NetProbe NetProbeCli
    RUNTIME DESTINATION . COMPONENT runtime
    BUNDLE DESTINATION . COMPONENT runtime
)
# The PATTERN excludes keep developer-local GeoLite2 downloads (gitignored, but
# present in data/ on machines that use the GeoIP feature) out of the ZIP.
install(DIRECTORY data/ DESTINATION data
    COMPONENT runtime
    PATTERN "*.mmdb" EXCLUDE
    PATTERN "*.tar.gz" EXCLUDE
)
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_LICENSES.md"
    DESTINATION .
    COMPONENT runtime
)
# packaging/README.md is the binary-user quick start; it lands at the ZIP root
# as README.md (install(FILES) keeps the basename).
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packaging/README.md"
    DESTINATION .
    COMPONENT runtime
)

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_FILE_NAME "NetProbe-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)
set(CPACK_COMPONENTS_ALL runtime)
include(CPack)

# --- 7.5 Sample PCAP generator ---
# Produces data/sample.pcap from a small generator program. The file is a build
# artifact (gitignored) but ends up in releases via the install rule above, so
# users can immediately try File → Open PCAP without admin rights.
add_executable(NetProbeMakeSamplePcap tools/make_sample_pcap.cpp)
target_include_directories(NetProbeMakeSamplePcap PRIVATE tests)

set(_netprobe_sample_pcap "${CMAKE_SOURCE_DIR}/data/sample.pcap")
add_custom_command(
    OUTPUT  "${_netprobe_sample_pcap}"
    COMMAND NetProbeMakeSamplePcap "${_netprobe_sample_pcap}"
    DEPENDS NetProbeMakeSamplePcap
    COMMENT "Generating data/sample.pcap"
    VERBATIM
)
add_custom_target(NetProbeSamplePcap ALL DEPENDS "${_netprobe_sample_pcap}")
add_dependencies(NetProbe NetProbeSamplePcap)

if(BUILD_TESTING)
    enable_testing()
    add_executable(NetProbeTests
        tests/parser_test.cpp
        tests/analysis_session_test.cpp
        tests/flow_exporter_test.cpp
        tests/flow_loss_test.cpp
        tests/malformed_test.cpp
    )
    # src/, pcap headers, and the crypto/geo libraries all arrive through
    # NetProbeCore's PUBLIC usage requirements.
    target_include_directories(NetProbeTests PRIVATE
        tests
    )
    target_link_libraries(NetProbeTests PRIVATE
        NetProbeCore
        GTest::gtest_main
    )
    target_compile_definitions(NetProbeTests PRIVATE
        LIBMAXMINDDB_TEST_DATA_DIR="${libmaxminddb_SOURCE_DIR}/t/maxmind-db/test-data"
    )
    # End-to-end CLI checks. These drive the real binary over the generated
    # sample capture, which is the only coverage of the complete chain from
    # pcap file through to an exported file.
    foreach(_netprobe_cli_format json csv)
        add_test(NAME CliExportsSampleFlowsAs${_netprobe_cli_format}
            COMMAND ${CMAKE_COMMAND}
                -DCLI=$<TARGET_FILE:NetProbeCli>
                -DPCAP=${CMAKE_SOURCE_DIR}/data/sample.pcap
                -DOUT=${CMAKE_CURRENT_BINARY_DIR}/cli-flows.${_netprobe_cli_format}
                -DFORMAT=${_netprobe_cli_format}
                -P ${CMAKE_SOURCE_DIR}/tests/check_cli_export.cmake)
    endforeach()

    # Usage errors must be distinguishable from runtime failures by exit code,
    # since that is what a calling script branches on.
    add_test(NAME CliRejectsMissingSource COMMAND NetProbeCli --output flows.json)
    set_tests_properties(CliRejectsMissingSource PROPERTIES WILL_FAIL TRUE)

    add_test(NAME CliShowsHelp COMMAND NetProbeCli --help)
    set_tests_properties(CliShowsHelp PROPERTIES
        PASS_REGULAR_EXPRESSION "Usage:")

    include(GoogleTest)
    # PRE_TEST defers the exe enumeration from build-time to ctest-time. On
    # Windows this matters because the test executable links wpcap.dll
    # transitively (via NpcapBackend), so running it at build time would fail
    # if the Npcap driver isn't installed — even though the build itself
    # completed successfully. With PRE_TEST, ctest is the only consumer that
    # actually needs the runtime DLL.
    gtest_discover_tests(NetProbeTests DISCOVERY_MODE PRE_TEST)
endif()

# --- 8. Fuzz Harnesses (optional) ---
# Build libFuzzer harnesses for the protocol parsers. Requires Clang (libFuzzer
# is a Clang-native instrumentation). On Windows, configure with the clang-cl
# toolchain shipped with Visual Studio rather than MSVC. The CI fuzz job runs
# Ubuntu + clang.
#
#   cmake -S . -B build -DBUILD_FUZZERS=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
#   cmake --build build --target NetProbeFuzzerSeeds NetProbeParserFuzzer
#   ./build/NetProbeFuzzerSeeds build/corpus
#   ./build/NetProbeParserFuzzer build/corpus -max_total_time=60
option(BUILD_FUZZERS "Build libFuzzer harnesses for the protocol parsers" OFF)

if(BUILD_FUZZERS)
    # The seed generator is plain C++ and always builds, even under MSVC, so a
    # Windows developer can inspect/regenerate the corpus without a Clang setup.
    add_executable(NetProbeFuzzerSeeds tests/fuzz/seed_generator.cpp)
    target_include_directories(NetProbeFuzzerSeeds PRIVATE tests)

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # NOTE: this target deliberately re-lists its sources instead of
        # linking NetProbeCore. libFuzzer needs every analyzed translation
        # unit built with -fsanitize=fuzzer coverage instrumentation, and
        # NetProbeCore is compiled without it. The list is also a curated
        # parser-only subset with no libpcap dependency. If you add a parser
        # to src/core that handles untrusted bytes, add it here too — see
        # NETPROBE_CORE_SOURCES above.
        add_executable(NetProbeParserFuzzer
            tests/fuzz/parser_fuzzer.cpp
            src/core/DNSParser.cpp
            src/core/ProtocolParser.cpp
            src/core/QuicParser.cpp
            src/core/QuicTracker.cpp
            src/core/TlsReassembler.cpp
        )
        target_include_directories(NetProbeParserFuzzer PRIVATE
            src
            ${PCAP_INCLUDE_DIR}
        )
        target_link_libraries(NetProbeParserFuzzer PRIVATE
            MbedTLS::mbedcrypto
            ${NETPROBE_CORE_PLATFORM_LIBRARIES}
        )
        target_compile_options(NetProbeParserFuzzer PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer -g)
        target_link_options(NetProbeParserFuzzer PRIVATE
            -fsanitize=fuzzer,address,undefined)
    else()
        message(STATUS
            "BUILD_FUZZERS=ON with non-Clang compiler '${CMAKE_CXX_COMPILER_ID}'. "
            "Only NetProbeFuzzerSeeds will be built — use clang/clang-cl for the "
            "fuzz harness itself.")
    endif()
endif()
