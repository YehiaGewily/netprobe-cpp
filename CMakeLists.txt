cmake_minimum_required(VERSION 3.20)
project(NetProbe VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)

# --- 1. Platform Capture Configuration ---
if(WIN32)
    set(NPCAP_SDK_PATH "C:/Npcap-SDK" CACHE PATH "Path to the Npcap SDK root")
    set(PCAP_INCLUDE_DIR "${NPCAP_SDK_PATH}/Include")
    set(NPCAP_LIB_DIR "${NPCAP_SDK_PATH}/Lib/x64")
    set(PCAP_LIBRARIES "${NPCAP_LIB_DIR}/wpcap.lib" "${NPCAP_LIB_DIR}/Packet.lib")

    if(NOT EXISTS "${PCAP_INCLUDE_DIR}/pcap.h")
        message(FATAL_ERROR "Npcap SDK was not found at ${NPCAP_SDK_PATH}. Install the SDK or set NPCAP_SDK_PATH.")
    endif()

    set(NETPROBE_APP_PLATFORM_LIBRARIES ws2_32 dwmapi opengl32)
    set(NETPROBE_TEST_PLATFORM_LIBRARIES ws2_32)
else()
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h pcap/pcap.h REQUIRED)
    find_library(PCAP_LIBRARY NAMES pcap REQUIRED)
    find_package(OpenGL REQUIRED)

    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    set(NETPROBE_APP_PLATFORM_LIBRARIES OpenGL::GL)
    set(NETPROBE_TEST_PLATFORM_LIBRARIES)
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
# Gather all source files
file(GLOB_RECURSE APP_SOURCES 
    "src/*.cpp" 
    "src/*.hpp"
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

# --- 4. Executable Target ---
add_executable(NetProbe 
    ${APP_SOURCES}
    ${IMGUI_BACKEND_SOURCES}
    ${IMGUI_CORE_SOURCES}
    ${IMPLOT_SOURCES}
)

# --- 5. Include Directories ---
target_include_directories(NetProbe PRIVATE
    include
    src
    ${PCAP_INCLUDE_DIR}
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
    ${implot_SOURCE_DIR}
)

# --- 6. Linking ---
target_link_libraries(NetProbe PRIVATE
    glfw
    nfd::nfd
    maxminddb::maxminddb
    ${PCAP_LIBRARIES}
    ${NETPROBE_APP_PLATFORM_LIBRARIES}
)
target_compile_definitions(NetProbe PRIVATE
    NETPROBE_GEOIP_DATA_DIR="${CMAKE_SOURCE_DIR}/data"
)

install(TARGETS NetProbe
    RUNTIME DESTINATION .
    BUNDLE DESTINATION .
)
install(DIRECTORY data/ DESTINATION data)

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_FILE_NAME "NetProbe-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
include(CPack)

if(BUILD_TESTING)
    enable_testing()
    add_executable(NetProbeTests
        tests/parser_test.cpp
        src/core/DNSParser.cpp
        src/core/FlowAggregator.cpp
        src/core/GeoIPResolver.cpp
        src/core/ProtocolParser.cpp
        src/capture/CaptureEngine.cpp
        src/capture/NpcapBackend.cpp
        src/capture/LibpcapBackend.cpp
    )
    target_include_directories(NetProbeTests PRIVATE
        src
        ${PCAP_INCLUDE_DIR}
    )
    target_link_libraries(NetProbeTests PRIVATE
        GTest::gtest_main
        maxminddb::maxminddb
        ${PCAP_LIBRARIES}
        ${NETPROBE_TEST_PLATFORM_LIBRARIES}
    )
    target_compile_definitions(NetProbeTests PRIVATE
        LIBMAXMINDDB_TEST_DATA_DIR="${libmaxminddb_SOURCE_DIR}/t/maxmind-db/test-data"
    )
    include(GoogleTest)
    gtest_discover_tests(NetProbeTests)
endif()

# Define generic Macros if needed
# target_compile_definitions(NetProbe PRIVATE ...)
