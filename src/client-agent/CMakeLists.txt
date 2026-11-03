cmake_minimum_required(VERSION 3.12.4)

project(wazuh-agentd C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
  list(APPEND CMAKE_MODULE_PATH "${SRC_FOLDER}/cmake")
  include(WazuhRpath)
endif()

# Include directories
include_directories(
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/shared/os_net/
  ${SRC_FOLDER}/shared/os_regex/
  ${SRC_FOLDER}/shared/os_xml/
  ${SRC_FOLDER}/shared/os_crypto/md5/
  ${SRC_FOLDER}/shared/os_crypto/sha1/
  ${SRC_FOLDER}/shared/os_crypto/sha256/
  ${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256/
  ${SRC_FOLDER}/shared/os_crypto/signature/
  ${SRC_FOLDER}/shared/include/error_messages/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/libyaml/include/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/openssl/include/
  ${SRC_FOLDER}/config/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/os_execd/include/
  ${SRC_FOLDER}/logcollector/include/
  ${SRC_FOLDER}/rootcheck/include/
  ${SRC_FOLDER}/syscheckd/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent/
  ${SRC_FOLDER}/wazuh_modules/sca/include/
  ${SRC_FOLDER}/shared_modules/agent_metadata/include/
  ${SRC_FOLDER}/shared_modules/common/
  ${CMAKE_CURRENT_SOURCE_DIR}/https_client/include/
  ${CMAKE_CURRENT_SOURCE_DIR}/include/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-DARGV0="wazuh-agentd")
add_definitions(-DGROUPGLOBAL="wazuh")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
  # os_win.h, for the service-state probe wazuh-agent-auth uses in place of a pid file.
  include_directories(${SRC_FOLDER}/win32/)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

# C++ HTTPS transport module (before the C glob so its sources never enter it)
add_subdirectory(https_client)

# Collect source files
file(GLOB AGENTD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(REMOVE_ITEM AGENTD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/agentd.c")
endif()

# Build static library (without main.c) for unit tests and Windows agent
list(REMOVE_ITEM AGENTD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
# The second entry point in this directory has to leave the library too, or agentd_lib carries
# two main() symbols and every unit-test binary that links its objects inherits one.
list(REMOVE_ITEM AGENTD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main-agent-auth.c")
add_library(agentd_lib STATIC ${AGENTD_SRC})
set_target_properties(agentd_lib PROPERTIES LINKER_LANGUAGE C)

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(agentd_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_options(agentd_lib PRIVATE -O0 -g)
endif()

target_link_libraries(agentd_lib PUBLIC wazuhext pthread agent_metadata config
                                        wazuh_modulesd_lib wazuh https_client)

if(UNIX)
  target_link_libraries(agentd_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(agentd_lib PUBLIC rt)
  endif(NOT APPLE)
endif(UNIX)

# Build Windows libraries (needed by Makefile for final win32 executables)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(wazuh-agentd STATIC ${AGENTD_SRC})
  target_compile_definitions(wazuh-agentd PUBLIC -D_WIN32_WINNT=0x600)
  if(UNIT_TEST)
    target_compile_definitions(wazuh-agentd PRIVATE WAZUH_UNIT_TESTING)
  endif()
  target_link_libraries(wazuh-agentd PRIVATE wazuhext pthread agent_metadata
                                             config wazuh_modulesd_lib wazuh
                                             https_client)

  if(NOT UNIT_TEST)
    # Standalone enrollment-token consumer (wazuh-agent-auth.exe). win32_service_rk carries
    # CheckServiceRunning(): the Windows equivalent of the pid-file probe, and the reason the
    # tool can refuse to run under a live agent. Built here rather than in win32/ so the
    # executable sits beside the sources it is made of.
    add_executable(
      wazuh-agent-auth-win
      ${CMAKE_CURRENT_SOURCE_DIR}/src/main-agent-auth.c
      ${SRC_FOLDER}/win32/agent_auth_stubs.c $<TARGET_OBJECTS:win32_service_rk>
      ${SRC_FOLDER}/win32/wazuh-agent-auth.rc ${RESOURCE_OBJ_APP})
    target_compile_definitions(wazuh-agent-auth-win PRIVATE _WIN32_WINNT=0x600)
    set_target_properties(
      wazuh-agent-auth-win
      PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin
                 OUTPUT_NAME wazuh-agent-auth)
    # Same mutual dependency as wazuh-agent.exe: the enrollment core reaches back into config
    # and the shared library, which reach forward again.
    target_link_libraries(
      wazuh-agent-auth-win
      PRIVATE -Wl,--start-group
              wazuh-agentd
              agent_metadata
              https_client
              config
              wazuh_modulesd_lib
              wazuh
              -Wl,--end-group
              ${WAZUH_WINDOWS_LIBS}
              wsock32
              advapi32
              kernel32
              iphlpapi
              ws2_32
              crypt32
              wintrust)
  endif()
  # Only build Unix executable when not running unit tests
elseif(NOT UNIT_TEST)
  add_executable(wazuh-agentd "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
  set_target_properties(
    wazuh-agentd PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY
                                              ${SRC_FOLDER}/build/bin)
  target_link_libraries(wazuh-agentd PRIVATE agentd_lib)

  wazuh_set_runtime_rpath(wazuh-agentd)

  # Standalone enrollment-token consumer. Deliberately not given its own ARGV0: that
  # macro is set for this whole directory above, and both overriding it here and moving it
  # per-target would change what agentd's own objects were compiled with. agent_auth_cli.c
  # carries its own name constant instead.
  add_executable(wazuh-agent-auth "${CMAKE_CURRENT_SOURCE_DIR}/src/main-agent-auth.c")
  set_target_properties(
    wazuh-agent-auth PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY
                                                  ${SRC_FOLDER}/build/bin)
  target_link_libraries(wazuh-agent-auth PRIVATE agentd_lib)

  # Without the rpath the binary cannot resolve libwazuhext.so from the install tree and exits
  # 127 before main() runs, which looks to a caller like the command not being installed at all.
  wazuh_set_runtime_rpath(wazuh-agent-auth)
endif()
