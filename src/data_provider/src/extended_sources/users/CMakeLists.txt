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
elseif(UNIX)
  set(SRC_FILES src/logged_in_users_unix.cpp)
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

add_library(logged_in_users STATIC ${SRC_FILES})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(logged_in_users
      psapi
      iphlpapi
      ws2_32
      wbemuuid
      advapi32
      kernel32
      user32
      gdi32
      winspool
      shell32
      uuid
      ole32
      oleaut32
      wtsapi32
  )
endif()

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(logged_in_users -fprofile-arcs)
  else()
    target_link_libraries(logged_in_users gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
endif(UNIT_TEST)
