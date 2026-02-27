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
    default-firewall-drop
    ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/default-firewall-drop.c)
  add_active_response_executable(pf
                                 ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/pf.c)
  add_active_response_executable(
    npf ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/npf.c)
  add_active_response_executable(
    ipfw ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalls/ipfw.c)

  # Build other active response programs
  add_active_response_executable(
    firewalld-drop ${CMAKE_CURRENT_SOURCE_DIR}/src/firewalld-drop.c)
  add_active_response_executable(
    disable-account ${CMAKE_CURRENT_SOURCE_DIR}/src/disable-account.c)
  add_active_response_executable(host-deny
                                 ${CMAKE_CURRENT_SOURCE_DIR}/src/host-deny.c)
  add_active_response_executable(
    ip-customblock ${CMAKE_CURRENT_SOURCE_DIR}/src/ip-customblock.c)
  add_active_response_executable(
    restart-wazuh ${CMAKE_CURRENT_SOURCE_DIR}/src/restart-wazuh.c)
  add_active_response_executable(route-null
                                 ${CMAKE_CURRENT_SOURCE_DIR}/src/route-null.c)
  add_active_response_executable(kaspersky
                                 ${CMAKE_CURRENT_SOURCE_DIR}/src/kaspersky.c)
  add_active_response_executable(wazuh-slack
                                 ${CMAKE_CURRENT_SOURCE_DIR}/src/wazuh-slack.c)
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

  # route-null.exe
  add_executable(
    route-null
    ${CMAKE_CURRENT_SOURCE_DIR}/src/route-null.c $<TARGET_OBJECTS:win32_stubs>
    ${SRC_FOLDER}/win32/route-null.rc ${RESOURCE_OBJ_APP})
  target_compile_definitions(route-null PRIVATE ARGV0="route-null")
  set_target_properties(
    route-null PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin
                          OUTPUT_NAME route-null)
  target_link_libraries(route-null PRIVATE wazuh ${WAZUH_WINDOWS_LIBS})

  # netsh.exe
  add_executable(
    netsh ${CMAKE_CURRENT_SOURCE_DIR}/src/netsh.c $<TARGET_OBJECTS:win32_stubs>
          ${SRC_FOLDER}/win32/netsh.rc ${RESOURCE_OBJ_APP})
  target_compile_definitions(netsh PRIVATE ARGV0="netsh")
  set_target_properties(netsh PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                         ${SRC_FOLDER}/build/bin OUTPUT_NAME netsh)
  target_link_libraries(netsh PRIVATE wazuh ${WAZUH_WINDOWS_LIBS})
endif()
