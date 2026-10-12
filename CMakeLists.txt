cmake_minimum_required(VERSION 3.16)
project(TacticalNIDS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Defensive compile flags
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -O2
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(include ${PCAP_INCLUDE_DIRS})

add_executable(tactical_nids
    src/main.cpp
    src/PacketParser.cpp
    src/DetectionEngine.cpp
    src/AlertLogger.cpp
)

target_link_libraries(tactical_nids PRIVATE ${PCAP_LIBRARIES} pthread)