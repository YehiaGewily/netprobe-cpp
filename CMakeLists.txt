cmake_minimum_required(VERSION 3.20)
project(NetProbe VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- 1. Npcap SDK Configuration ---
set(NPCAP_SDK_PATH "C:/Npcap-SDK")

if(NOT EXISTS "${NPCAP_SDK_PATH}")
    message(WARNING "Npcap SDK not found at ${NPCAP_SDK_PATH}. Please ensure it is installed.")
else()
    message(STATUS "Found Npcap SDK path: ${NPCAP_SDK_PATH}")
    if(EXISTS "${NPCAP_SDK_PATH}/Include/pcap.h")
        message(STATUS "Found pcap.h in ${NPCAP_SDK_PATH}/Include")
    else()
        message(WARNING "Could NOT find pcap.h in ${NPCAP_SDK_PATH}/Include. Check directory structure.")
    endif()
endif()

# Define Npcap Libraries manually
set(NPCAP_INCLUDE_DIR "${NPCAP_SDK_PATH}/Include")
set(NPCAP_LIB_DIR "${NPCAP_SDK_PATH}/Lib/x64")
set(NPCAP_LIBS "${NPCAP_LIB_DIR}/wpcap.lib" "${NPCAP_LIB_DIR}/Packet.lib")

# --- 2. FetchContent Dependencies (Gui Stack) ---
include(FetchContent)

# GLFW
message(STATUS "Fetching GLFW...")
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
    GIT_TAG        docking
)
FetchContent_MakeAvailable(imgui)

# ImPlot
message(STATUS "Fetching ImPlot...")
FetchContent_Declare(
    implot
    GIT_REPOSITORY https://github.com/epezent/implot
    GIT_TAG        master
)
FetchContent_MakeAvailable(implot)

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
    ${NPCAP_INCLUDE_DIR}
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
    ${implot_SOURCE_DIR}
)

# --- 6. Linking ---
target_link_libraries(NetProbe PRIVATE
    glfw
    ${NPCAP_LIBS}
    ws2_32  # Windows Sockets
    dwmapi  # Usually needed for modern Windows UI/ImGui
    opengl32
)

# Define generic Macros if needed
# target_compile_definitions(NetProbe PRIVATE ...)
