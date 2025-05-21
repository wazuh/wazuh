cmake_minimum_required(VERSION 3.10)

project(logged_in_users)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../external/nlohmann/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include_directories(${CMAKE_SOURCE_DIR}/../shared_modules/utils)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(SRC_FILES src/logged_in_users_win.cpp)
  set(SRC_FILES_USERS src/users_windows.cpp src/users_windows_utils_wrapper.cpp)
  set(PLATFORM_LIBS_USERS netapi32 advapi32)
else()
  set(SRC_FILES src/logged_in_users_unix.cpp)

  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(OPEN_DIRECTORY OpenDirectory)
    find_library(FOUNDATION Foundation)

    set(SRC_FILES_USERS src/users_darwin.cpp src/od_wrapper.mm)
    set(PLATFORM_LIBS_USERS ${OPEN_DIRECTORY} ${FOUNDATION})
  else()
    set(SRC_FILES_USERS src/users_linux.cpp)
  endif()
endif()

add_library(logged_in_users STATIC ${SRC_FILES})
add_library(users_collector STATIC ${SRC_FILES_USERS})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(logged_in_users
      wtsapi32
  )
endif()

if(PLATFORM_LIBS_USERS)
    target_link_libraries(users_collector ${PLATFORM_LIBS_USERS})
endif()

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(logged_in_users -fprofile-arcs)
    target_link_libraries(users_collector -fprofile-arcs)
  else()
    target_link_libraries(logged_in_users gcov)
    target_link_libraries(users_collector gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
endif(UNIT_TEST)
