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

# Build Unix/Linux/macOS active responses
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # Build firewall-related active responses
  add_active_response_executable(
    block-ip-iptables
    ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/block-ip-iptables.c)
  add_active_response_executable(
    block-ip-pf ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/block-ip-pf.c)
  add_active_response_executable(
    block-ip-npf ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/block-ip-npf.c)
  add_active_response_executable(
    block-ip-ipfw ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/block-ip-ipfw.c)

  # Build other active response programs
  add_active_response_executable(
    block-ip-firewalld ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-firewalld.c)
  add_active_response_executable(
    disable-account ${CMAKE_CURRENT_SOURCE_DIR}/src/disable-account.c)
  add_active_response_executable(
    block-ip-hostsdeny ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-hostsdeny.c)
  add_active_response_executable(
    block-ip-custom ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-custom.c)
  add_active_response_executable(
    restart-wazuh ${CMAKE_CURRENT_SOURCE_DIR}/src/restart-wazuh.c)
  add_active_response_executable(
    block-ip-route ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-route.c)
  add_active_response_executable(
    scan-kaspersky ${CMAKE_CURRENT_SOURCE_DIR}/src/scan-kaspersky.c)
  add_active_response_executable(
    notify-slack ${CMAKE_CURRENT_SOURCE_DIR}/src/notify-slack.c)
endif()

# Build Windows active responses
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # Windows active responses need win32_stubs and resource files (.rc)

  # restart-wazuh.exe
  add_executable(
    restart-wazuh
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restart-wazuh.c
    $<TARGET_OBJECTS:win32_stubs> ${SRC_FOLDER}/win32/restart-wazuh.rc
    ${RESOURCE_OBJ_APP})
  target_compile_definitions(restart-wazuh PRIVATE ARGV0="restart-wazuh")
  set_target_properties(
    restart-wazuh PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin
                             OUTPUT_NAME restart-wazuh)
  target_link_libraries(restart-wazuh PRIVATE wazuh ${WAZUH_WINDOWS_LIBS})

  # block-ip-route.exe
  add_executable(
    block-ip-route
    ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-route.c $<TARGET_OBJECTS:win32_stubs>
    ${SRC_FOLDER}/win32/block-ip-route.rc ${RESOURCE_OBJ_APP})
  target_compile_definitions(block-ip-route PRIVATE ARGV0="block-ip-route")
  set_target_properties(
    block-ip-route PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin
                              OUTPUT_NAME block-ip-route)
  target_link_libraries(block-ip-route PRIVATE wazuh ${WAZUH_WINDOWS_LIBS})

  # block-ip-netsh.exe
  add_executable(
    block-ip-netsh ${CMAKE_CURRENT_SOURCE_DIR}/src/block-ip-netsh.c
    $<TARGET_OBJECTS:win32_stubs> ${SRC_FOLDER}/win32/block-ip-netsh.rc ${RESOURCE_OBJ_APP})
  target_compile_definitions(block-ip-netsh PRIVATE ARGV0="block-ip-netsh")
  set_target_properties(block-ip-netsh PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                         ${SRC_FOLDER}/build/bin OUTPUT_NAME block-ip-netsh)
  target_link_libraries(block-ip-netsh PRIVATE wazuh ${WAZUH_WINDOWS_LIBS})
endif()
