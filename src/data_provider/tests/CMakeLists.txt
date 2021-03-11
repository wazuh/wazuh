cmake_minimum_required(VERSION 3.12.4)

project(unit_tests)

include_directories(${CMAKE_SOURCE_DIR})

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

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
  add_subdirectory(sysInfoWin)
  add_subdirectory(sysInfoNetworkWindows)
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -fprofile-arcs ")
else()
  string(APPEND CMAKE_EXE_LINKER_FLAGS " -lgcov ")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

add_subdirectory(sysInfo)
add_subdirectory(sysInfoPorts)