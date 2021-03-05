cmake_minimum_required(VERSION 3.12.4)

project(sysinfo)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

enable_testing()

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14")

set(CMAKE_CXX_FLAGS_DEBUG "-g")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif(FSANITIZE)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${SRC_FOLDER}/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/procps/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/libplist/bin/include/)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/procps/)
link_directories(${SRC_FOLDER}/external/bzip2/)
link_directories(${SRC_FOLDER}/external/libplist/bin/lib/)


if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Win.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsInfoWin.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*Windows.cpp")
  add_definitions(-DWIN32=1
                  -D_WIN32_WINNT=0x600
                  -DWIN_EXPORT)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Linux.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*Linux.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Mac.cpp"
      "${CMAKE_SOURCE_DIR}/src/*CommonBSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/packages/*Mac.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*BSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*FreeBSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/*CommonBSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*BSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*OpenBSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/*CommonBSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*BSD.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
else()
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Unix.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")


add_library(sysinfo SHARED
    ${SYSINFO_SRC}
    ${CMAKE_SOURCE_DIR}/src/sysInfo.cpp )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(sysinfo psapi iphlpapi ws2_32)
  set_target_properties(sysinfo PROPERTIES
      PREFIX ""
      SUFFIX ".dll"
      LINK_FLAGS "-Wl,--add-stdcall-alias -static-libgcc -static-libstdc++"
      POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
      # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  set_target_properties(sysinfo PROPERTIES
          LINK_FLAGS "-static-libgcc -static-libstdc++")

  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
    if(DISABLE_SHARED)
      target_link_libraries(sysinfo proc)
    endif(DISABLE_SHARED)
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  else()
    string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
    string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
    target_link_libraries(sysinfo -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR})
  endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
elseif(APPLE)
  target_link_libraries(sysinfo cjson ${SRC_FOLDER}/external/libplist/bin/lib/libplist-2.0.a)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(DISABLE_SHARED)
  target_link_libraries(sysinfo cjson)
else()
  target_link_libraries(sysinfo wazuhext)
endif(DISABLE_SHARED)

if(APPLE)
  add_custom_command(TARGET sysinfo
    POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -id "@rpath/libsysinfo.dylib"
    $<TARGET_FILE:sysinfo>)
endif(APPLE)

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(sysinfo -fprofile-arcs)
  else()
    target_link_libraries(sysinfo gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
else()
  if(FSANITIZE)
      target_link_libraries(sysinfo gcov)
  endif(FSANITIZE)
  add_subdirectory(testtool)
endif(UNIT_TEST)
