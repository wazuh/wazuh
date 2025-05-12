cmake_minimum_required(VERSION 3.10)
project(logged_in_users)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../../../../external/nlohmann/)

if(UNIX)
    set(SRC_FILES src/logged_in_users_unix.cpp)
elseif(WIN32)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

add_library(logged_in_users STATIC ${SRC_FILES})

if(UNIT_TEST)
  add_subdirectory(tests)
endif()
