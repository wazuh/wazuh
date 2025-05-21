cmake_minimum_required(VERSION 3.10)

project(users)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/../external/nlohmann/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include_directories(${CMAKE_SOURCE_DIR}/../shared_modules/utils)
endif()

set(SRC_FILES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND SRC_FILES src/logged_in_users_win.cpp)
  list(APPEND SRC_FILES src/users_windows.cpp src/users_windows_utils_wrapper.cpp)
  set(PLATFORM_LIBS_USERS netapi32 advapi32)
else()
  list(APPEND SRC_FILES src/logged_in_users_unix.cpp)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND SRC_FILES src/shadow_linux.cpp)
    list(APPEND SRC_FILES src/users_linux.cpp)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(OPEN_DIRECTORY OpenDirectory)
    find_library(FOUNDATION Foundation)

    list(APPEND SRC_FILES src/users_darwin.cpp src/od_wrapper.mm)
    set(PLATFORM_LIBS_USERS ${OPEN_DIRECTORY} ${FOUNDATION})
  endif()
endif()

add_library(users STATIC ${SRC_FILES})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(users
      wtsapi32
      ${PLATFORM_LIBS_USERS}
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_link_libraries(users ${PLATFORM_LIBS_USERS})
endif()

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(users -fprofile-arcs)
  else()
    target_link_libraries(users gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
endif(UNIT_TEST)
