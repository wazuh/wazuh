cmake_minimum_required(VERSION 2.6.4)

project(unit_tests)

include_directories(${CMAKE_SOURCE_DIR})

add_subdirectory(sysInfo)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_subdirectory(sysInfoNetworkLinux)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_subdirectory(sysInfoNetworkBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  add_subdirectory(sysInfoNetworkBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  add_subdirectory(sysInfoNetworkBSD)
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")