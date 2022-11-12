project(sysinfo)

include_directories(${PROJECT_SOURCE_DIR}/src/)
include_directories(${PROJECT_SOURCE_DIR}/include/)

if(NOT CMAKE_CHECK_CENTOS5) # Avoid incompatible libraries in CentOS 5 and Red Hat 5
include_directories(${SRC_FOLDER}/external/pacman/lib/libalpm/)
include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)
include_directories(${SRC_FOLDER}/external/rpm/builddir/output/include/)

link_directories(${SRC_FOLDER}/external/pacman/lib/libalpm/)
link_directories(${SRC_FOLDER}/external/libarchive/.libs/)
link_directories(${SRC_FOLDER}/external/rpm/builddir/)
endif(NOT CMAKE_CHECK_CENTOS5)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/*Win.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsInfoWin.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/*Windows.cpp"
      "${PROJECT_SOURCE_DIR}/src/packages/*Windows.cpp")
  add_definitions(-DWIN32=1
                  -D_WIN32_WINNT=0x600
                  -DWIN_EXPORT)
elseif(CMAKE_CHECK_CENTOS5)
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/*Linux.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/*Linux.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp"
      "${PROJECT_SOURCE_DIR}/src/packages/packageLinuxParser.cpp"
      "${PROJECT_SOURCE_DIR}/src/packages/packageLinuxParserRpmLegacy.cpp")
  add_definitions(-DLINUX_TYPE=LinuxType::LEGACY) # Partial compilation in legacy systems
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/*Linux.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/*Linux.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp"
      "${PROJECT_SOURCE_DIR}/src/packages/packageLinux*.cpp"
      "${PROJECT_SOURCE_DIR}/src/packages/rpm*.cpp")
  add_definitions(-DLINUX_TYPE=LinuxType::STANDARD) # Standard compilation in compatible systems
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/*Mac.cpp"
      "${PROJECT_SOURCE_DIR}/src/*CommonBSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/packages/*Mac.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/*BSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/*FreeBSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/*CommonBSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/*BSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/*OpenBSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/*CommonBSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/*BSD.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/UtilsWrapperUnix.cpp"
      "${PROJECT_SOURCE_DIR}/src/*Solaris.cpp"
      "${PROJECT_SOURCE_DIR}/src/packages/*Solaris.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/networkSolarisHelper.cpp"
      "${PROJECT_SOURCE_DIR}/src/network/*Solaris.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
else()
  file(GLOB SYSINFO_SRC
      "${PROJECT_SOURCE_DIR}/src/*Unix.cpp"
      "${PROJECT_SOURCE_DIR}/src/osinfo/sysOsParsers.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")


add_library(sysinfo SHARED
    ${SYSINFO_SRC}
    ${PROJECT_SOURCE_DIR}/src/sysInfo.cpp )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(sysinfo psapi iphlpapi ws2_32)
  set_target_properties(sysinfo PROPERTIES
      PREFIX ""
      SUFFIX ".dll"
      LINK_FLAGS "-Wl,--add-stdcall-alias"
      POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
      # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  else()
    string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
    string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
    target_link_libraries(sysinfo -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR})
  endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
elseif(APPLE)
  target_link_libraries(sysinfo cjson ${SRC_FOLDER}/external/libplist/bin/lib/libplist-2.0.a)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(sysinfo wazuhext)


if(APPLE)
  add_custom_command(TARGET sysinfo
    POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -id "@rpath/libsysinfo.dylib"
    $<TARGET_FILE:sysinfo>)
endif(APPLE)

add_subdirectory(testtool)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
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
endif()
