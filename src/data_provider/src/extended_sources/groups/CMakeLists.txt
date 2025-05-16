cmake_minimum_required(VERSION 3.10)
project(user_groups)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../../../../external/nlohmann/)

if(LINUX)
    set(SRC_FILES src/user_groups_linux.cpp)
elseif(WIN32)
    set(SRC_FILES src/user_groups_windows.cpp)
elseif(APPLE)
    find_library(OPEN_DIRECTORY OpenDirectory)
    find_library(FOUNDATION Foundation)

    set(SRC_FILES src/user_groups_darwin.cpp src/od_wrapper.mm)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

add_library(user_groups STATIC ${SRC_FILES})

if(APPLE)
    target_link_libraries(user_groups ${FOUNDATION} ${OPEN_DIRECTORY})
endif()

if(UNIT_TEST)
    add_subdirectory(tests)
endif()
