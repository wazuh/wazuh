cmake_minimum_required(VERSION 3.12.4)

project(enrollment-simulator)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set default build type to Debug if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++17")

# Debug flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

if(FSANITIZE)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pthread -fsanitize=address,leak,undefined")
endif(FSANITIZE)

# Find required libraries
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# No include directories needed - headers are in src/

# Source files
set(ENROLLMENT_SIMULATOR_SOURCES
    src/main.cpp
    src/types.cpp
    src/network_utils.cpp
    src/agent_config.cpp
    src/statistics.cpp
    src/csv_exporter.cpp
    src/simulator.cpp
)

# Create the executable
add_executable(enrollment-simulator ${ENROLLMENT_SIMULATOR_SOURCES})

# Link libraries
target_link_libraries(enrollment-simulator
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Platform-specific configurations
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Additional Linux-specific libraries if needed
    target_link_libraries(enrollment-simulator dl)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # macOS specific configurations if needed
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Windows specific configurations if needed
    target_link_libraries(enrollment-simulator ws2_32)
endif()

# Installation (optional)
# install(TARGETS enrollment-simulator DESTINATION bin)

# Optional: Generate compile commands for better IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
