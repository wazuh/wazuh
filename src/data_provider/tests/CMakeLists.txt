cmake_minimum_required(VERSION 3.12.4)

project(unit_tests)

include_directories(${CMAKE_SOURCE_DIR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_subdirectory(sysInfoPackagesLinuxHelper)
  add_subdirectory(sysInfoNetworkLinux)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_subdirectory(sysInfoNetworkBSD)
  add_subdirectory(sysInfoPackagesMAC)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  add_subdirectory(sysInfoNetworkBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  add_subdirectory(sysInfoNetworkBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_subdirectory(sysInfoNetworkWindows)  
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

add_subdirectory(sysInfo)
add_subdirectory(sysInfoPorts)