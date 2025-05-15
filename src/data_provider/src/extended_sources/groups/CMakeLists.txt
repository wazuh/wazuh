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
elseif(DARWIN)
    set(SRC_FILES src/user_groups_darwin.cpp)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

add_library(user_groups STATIC ${SRC_FILES})

if(UNIT_TEST)
  add_subdirectory(tests)
endif()
