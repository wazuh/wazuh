cmake_minimum_required(VERSION 3.12.4)

project(wazuh-active-response C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Skip building active responses during unit tests
if(UNIT_TEST)
  return()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${SRC_FOLDER}/config/include)
include_directories(${SRC_FOLDER}/shared/include/error_messages)
include_directories(${SRC_FOLDER}/shared/include)
include_directories(${SRC_FOLDER}/shared/os_regex)
include_directories(${SRC_FOLDER}/shared/os_crypto/sha1)
include_directories(${SRC_FOLDER}/shared/os_xml)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/curl/include/curl/)
include_directories(${SRC_FOLDER}/external/libpcre2/include/)
include_directories(${SRC_FOLDER}/external/libyaml/include)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/sqlite/)

# Platform-specific definitions
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -D_POSIX_C_SOURCE -DPSAPI_VERSION=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

# Define function to create active response executable for Unix-like systems
function(add_active_response_executable name source)
  add_executable(${name} ${source})

  # Set ARGV0 definition for each binary
  target_compile_definitions(${name} PRIVATE ARGV0="${name}")

  # Set output directory to src/build/bin
  set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                           ${SRC_FOLDER}/build/bin OUTPUT_NAME ${name})

  # Link with libwazuh.a
  target_link_libraries(${name} PRIVATE wazuh)

  # Platform-specific linker flags
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Linux: Set runtime library path and link system libraries
    set_target_properties(${name} PROPERTIES
      INSTALL_RPATH "$ORIGIN/../../lib"
      BUILD_WITH_INSTALL_RPATH TRUE)
    target_link_options(${name} PRIVATE -pthread)

    # Add system libraries
    target_link_libraries(${name} PRIVATE pthread rt dl m)

  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # macOS: Add rpath for @executable_path/../../lib, plus pthread
    target_link_options(${name} PRIVATE -pthread)
    set_target_properties(
      ${name} PROPERTIES INSTALL_RPATH "@executable_path/../../lib"
                         BUILD_WITH_INSTALL_RPATH TRUE)

    # Add macOS frameworks
    target_link_libraries(
      ${name} PRIVATE "-framework Security" "-framework CoreFoundation"
                      "-framework SystemConfiguration")
  endif()
endfunction()

# Build Unix/Linux/BSD unified block-ip active response
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  # Unified block-ip for Linux, FreeBSD, OpenBSD, NetBSD
  add_active_response_executable(
    block-ip
    ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-unix.c)

  # Add helpers for firewall operations
  target_sources(block-ip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/helpers/firewall_helpers.c)
  target_include_directories(block-ip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/helpers)

  # Platform-specific compile definitions
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(block-ip PRIVATE PLATFORM_LINUX=1)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    target_compile_definitions(block-ip PRIVATE PLATFORM_FREEBSD=1)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_compile_definitions(block-ip PRIVATE PLATFORM_OPENBSD=1)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    target_compile_definitions(block-ip PRIVATE PLATFORM_NETBSD=1)
  endif()

  # Build other Unix/Linux/BSD active response programs
  add_active_response_executable(
    disable-account ${CMAKE_CURRENT_SOURCE_DIR}/src/disable-account.c)
endif()

# Build macOS-specific block-ip active response
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  # macOS uses separate block-ip binary with pf only
  add_active_response_executable(
    block-ip
    ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-macos.c)

  # Add helpers for firewall operations
  target_sources(block-ip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/helpers/firewall_helpers.c)
  target_include_directories(block-ip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/helpers)

  target_compile_definitions(block-ip PRIVATE PLATFORM_MACOS=1)

  # Build other macOS active response programs
  add_active_response_executable(
    disable-account ${CMAKE_CURRENT_SOURCE_DIR}/src/disable-account.c)
endif()

# Build Windows active responses
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # Windows active responses need win32_stubs and resource files (.rc)

  # Unified block-ip.exe (netsh + route fallback)
  add_executable(
    block-ip
    ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-windows.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/helpers/firewall_helpers.c
    $<TARGET_OBJECTS:win32_stubs>
    ${SRC_FOLDER}/win32/block-ip.rc
    ${RESOURCE_OBJ_APP})
  target_compile_definitions(block-ip PRIVATE ARGV0="block-ip" PLATFORM_WINDOWS=1)
  target_include_directories(block-ip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/helpers)
  set_target_properties(
    block-ip PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin
                       OUTPUT_NAME block-ip)
  target_link_libraries(block-ip PRIVATE wazuh ${WAZUH_WINDOWS_LIBS})
endif()
