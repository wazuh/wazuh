cmake_minimum_required(VERSION 3.12.4)

project(sysinfo)

if(NOT CMAKE_BUILD_TYPE)
  if(CMAKE_SYMBOLS_IN_RELEASE MATCHES "ON")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  else()
    set(CMAKE_BUILD_TYPE Release)
  endif()
endif()

enable_testing()

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

include(CheckCXXSourceCompiles)
set(CMAKE_CXX_STANDARD 17)
#Check if std::optional is available, therefore C++17 is available
check_cxx_source_compiles("
    #include <optional>
    int main() {
        std::optional<int> o;
        return 0;
    }
" HAS_OPTIONAL)

if(NOT HAS_OPTIONAL AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_CXX_STANDARD 14)
endif()

#Check if filesystem is available
check_cxx_source_compiles("
    #include <filesystem>
    int main() {
        std::filesystem::path p;
        return 0;
    }
" HAS_FILESYSTEM)

if(HAS_FILESYSTEM OR CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DHAS_STDFILESYSTEM=true)
else()
  add_definitions(-DHAS_STDFILESYSTEM=false)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -fPIC")

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
include_directories(${CMAKE_SOURCE_DIR}/src/extended_sources/groups/include)
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
include_directories(${SRC_FOLDER}/external/libdb/build_unix/)
if(NOT CMAKE_CHECK_CENTOS5) # Avoid incompatible libraries in CentOS 5 and Red Hat 5
  include_directories(${SRC_FOLDER}/external/pacman/lib/libalpm/)
  include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)
  include_directories(${SRC_FOLDER}/external/rpm/builddir/output/include/)
endif(NOT CMAKE_CHECK_CENTOS5)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # Avoid download externals from http-request submodule
  set(EXTERNAL_RES "")
  set(PRECOMPILED_EXTERNAL_RES "")
  include_directories(${SRC_FOLDER}/shared_modules/http-request/include/)
  include_directories(${SRC_FOLDER}/shared_modules/http-request/shared/)
  include_directories(${CMAKE_SOURCE_DIR}/src/extended_sources/wrappers/unix/)
  include_directories(${CMAKE_SOURCE_DIR}/src/extended_sources/wrappers/unix/linux)
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

if(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
  link_directories(${INSTALL_PREFIX}/lib)
endif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  link_directories(${CMAKE_SOURCE_DIR}/lib/)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/procps/)
link_directories(${SRC_FOLDER}/external/bzip2/)
link_directories(${SRC_FOLDER}/external/libplist/bin/lib/)
link_directories(${SRC_FOLDER}/external/libdb/build_unix/)
if(NOT CMAKE_CHECK_CENTOS5) # Avoid incompatible libraries in CentOS 5 and Red Hat 5
link_directories(${SRC_FOLDER}/external/pacman/lib/libalpm/)
link_directories(${SRC_FOLDER}/external/libarchive/.libs/)
link_directories(${SRC_FOLDER}/external/rpm/builddir/)
endif(NOT CMAKE_CHECK_CENTOS5)
link_directories(${SRC_FOLDER}/external/openssl/)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  link_directories(${SRC_FOLDER}/shared_modules/http-request/build)
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  link_directories(${SRC_FOLDER}/external/curl/lib/.libs/)


if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Win.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsInfoWin.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*Windows.cpp"
      "${CMAKE_SOURCE_DIR}/src/packages/*Windows.cpp")
  add_definitions(-DWIN32=1
                  -D_WIN32_WINNT=0x600
                  -DWIN_EXPORT)
elseif(CMAKE_CHECK_CENTOS5)
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Linux.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*Linux.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp"
      "${CMAKE_SOURCE_DIR}/src/packages/packageLinuxParser.cpp"
      "${CMAKE_SOURCE_DIR}/src/packages/packageLinuxParserRpmLegacy.cpp")
  add_definitions(-DLINUX_TYPE=LinuxType::LEGACY) # Partial compilation in legacy systems
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Linux.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*Linux.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp"
      "${CMAKE_SOURCE_DIR}/src/packages/packageLinux*.cpp"
      "${CMAKE_SOURCE_DIR}/src/packages/rpm*.cpp")
  add_definitions(-DLINUX_TYPE=LinuxType::STANDARD) # Standard compilation in compatible systems
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  if(${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES "arm64.*|ARM64.*")
    file(GLOB SYSINFO_SRC
        "${CMAKE_SOURCE_DIR}/src/*Mac.cpp"
        "${CMAKE_SOURCE_DIR}/src/*CommonBSD.cpp"
        "${CMAKE_SOURCE_DIR}/src/packages/*Mac.cpp"
        "${CMAKE_SOURCE_DIR}/src/network/*BSD.cpp"
        "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp"
        "${CMAKE_SOURCE_DIR}/src/hardware/*ARMMac.cpp")
  else()
    file(GLOB SYSINFO_SRC
        "${CMAKE_SOURCE_DIR}/src/*Mac.cpp"
        "${CMAKE_SOURCE_DIR}/src/*CommonBSD.cpp"
        "${CMAKE_SOURCE_DIR}/src/packages/*Mac.cpp"
        "${CMAKE_SOURCE_DIR}/src/network/*BSD.cpp"
        "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp"
        "${CMAKE_SOURCE_DIR}/src/hardware/*X86_64Mac.cpp")
  endif()
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
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/UtilsWrapperUnix.cpp"
      "${CMAKE_SOURCE_DIR}/src/*Solaris.cpp"
      "${CMAKE_SOURCE_DIR}/src/packages/*Solaris.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/networkSolarisHelper.cpp"
      "${CMAKE_SOURCE_DIR}/src/network/*Solaris.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
else()
  file(GLOB SYSINFO_SRC
      "${CMAKE_SOURCE_DIR}/src/*Unix.cpp"
      "${CMAKE_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

#TODO: should use a define to disable this?
add_subdirectory(src/extended_sources)

add_library(sysinfo SHARED
    ${SYSINFO_SRC}
    ${CMAKE_SOURCE_DIR}/src/sysInfo.cpp
    ${SRC_FOLDER}/${RESOURCE_OBJ})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(sysinfo psapi iphlpapi ws2_32 wbemuuid uuid wuguid ole32 oleaut32)
  set_target_properties(sysinfo PROPERTIES
      PREFIX ""
      SUFFIX ".dll"
      LINK_FLAGS "-Wl,--add-stdcall-alias"
      POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
      # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
    string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
    target_link_libraries(sysinfo -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR})
  elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
    # Do nothing for HP-UX
  else()
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  endif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
elseif(APPLE)
  find_library(iokit_lib IOKit)
  if(NOT iokit_lib)
    message(FATAL_ERROR "IOKit library not found! Aborting...")
  endif()
  find_library(corefoundation_lib CoreFoundation)
  if(NOT corefoundation_lib)
    message(FATAL_ERROR "CoreFoundation library not found! Aborting...")
  endif()
  target_link_libraries(sysinfo cjson ${SRC_FOLDER}/external/libplist/bin/lib/libplist-2.0.a ${iokit_lib} ${corefoundation_lib})
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(sysinfo groups wazuhext)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CURL_DEP "wazuhext")
  target_link_libraries(sysinfo urlrequest db)
  if(CMAKE_CHECK_CENTOS5)
      set(USE_HTTP 1)
  endif(CMAKE_CHECK_CENTOS5)
  add_subdirectory(${SRC_FOLDER}/shared_modules/http-request ${SRC_FOLDER}/shared_modules/http-request/build)
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

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
