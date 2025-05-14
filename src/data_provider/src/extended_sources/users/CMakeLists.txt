cmake_minimum_required(VERSION 3.10)
project(logged_in_users)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../../../../external/nlohmann/)

if(UNIX)
    set(SRC_FILES_LOGGED_USERS src/logged_in_users_unix.cpp)

    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(SRC_FILES_USERS src/users_darwin.cpp)
    else()
        set(SRC_FILES_USERS src/users_linux.cpp)
    endif()
elseif(WIN32)
   set(SRC_FILES_LOGGED_USERS src/logged_in_users_windows.cpp)
   set(SRC_FILES_USERS src/users_windows.cpp)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

add_library(logged_in_users_collector STATIC ${SRC_FILES_LOGGED_USERS})
add_library(users_collector STATIC ${SRC_FILES_USERS})

if(UNIT_TEST)
  add_subdirectory(tests)
endif()
