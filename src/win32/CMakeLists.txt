cmake_minimum_required(VERSION 3.12.4)

project(wazuh-win32 C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# This module is Windows-only
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  return()
endif()

# ──────────────────────────────────────────────────────────────────────────────
# Common definitions and include directories
# ──────────────────────────────────────────────────────────────────────────────

add_definitions(-DWIN32=1 -DCLIENT -D_POSIX_C_SOURCE -DPSAPI_VERSION=1)

include_directories(
  ${SRC_FOLDER}/
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/shared/include/error_messages/
  ${SRC_FOLDER}/shared/os_crypto/md5/
  ${SRC_FOLDER}/shared/os_crypto/sha1/
  ${SRC_FOLDER}/shared/os_crypto/sha256/
  ${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256/
  ${SRC_FOLDER}/shared/os_crypto/blowfish/
  ${SRC_FOLDER}/shared/os_crypto/signature/
  ${SRC_FOLDER}/shared/os_net/
  ${SRC_FOLDER}/shared/os_regex/
  ${SRC_FOLDER}/shared/os_xml/
  ${SRC_FOLDER}/config/include/
  ${SRC_FOLDER}/client-agent/include/
  ${SRC_FOLDER}/logcollector/include/
  ${SRC_FOLDER}/os_execd/include/
  ${SRC_FOLDER}/syscheckd/include/
  ${SRC_FOLDER}/rootcheck/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/shared_modules/agent_metadata/include/
  ${SRC_FOLDER}/shared_modules/common/
  ${SRC_FOLDER}/shared_modules/dbsync/include/
  ${SRC_FOLDER}/shared_modules/sync_protocol/include/
  ${SRC_FOLDER}/shared_modules/router/include/
  ${SRC_FOLDER}/shared_modules/content_manager/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager/
  ${SRC_FOLDER}/wazuh_modules/src/task_manager/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/libyaml/include/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/openssl/include/
  ${SRC_FOLDER}/external/zlib/
  ${SRC_FOLDER}/external/msgpack/include/)

# Common Windows system libraries (maps to OSSEC_LIBS in the Makefile)
set(WIN_SYSTEM_LIBS
    wsock32
    wevtapi
    shlwapi
    comctl32
    advapi32
    kernel32
    psapi
    gdi32
    iphlpapi
    ws2_32
    crypt32
    wintrust)

set(WAZUHEXT_LIB ${SRC_FOLDER}/libwazuhext.lib)

# ──────────────────────────────────────────────────────────────────────────────
# Object libraries – shared code compiled with different flags
# ──────────────────────────────────────────────────────────────────────────────

# win32_common: core Windows sources compiled with OSSECHIDS +
# ARGV0="wazuh-agent"
add_library(
  win32_common OBJECT
  ${CMAKE_CURRENT_SOURCE_DIR}/win_agent.c
  ${CMAKE_CURRENT_SOURCE_DIR}/win_service.c
  ${CMAKE_CURRENT_SOURCE_DIR}/win_utils.c)
target_compile_definitions(win32_common PRIVATE OSSECHIDS ARGV0="wazuh-agent"
                                                _WIN32_WINNT=0x600)

# Enable WAZUH_UNIT_TESTING to activate wrapper macros for unit tests
if(UNIT_TEST)
  target_compile_definitions(win32_common PRIVATE WAZUH_UNIT_TESTING)
endif()

# win32_service_rk: win_service.c compiled WITHOUT OSSECHIDS (for setup/UI
# tools) Equivalent to the Makefile's "win32/%_rk.o: win32/%.c" pattern rule
add_library(win32_service_rk OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/win_service.c)
target_compile_definitions(win32_service_rk PRIVATE ARGV0="wazuh-agent"
                                                    _WIN32_WINNT=0x600)

# win32_setup: shared setup code
add_library(win32_setup OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/setup-shared.c)
target_compile_definitions(win32_setup PRIVATE ARGV0="wazuh-agent"
                                               _WIN32_WINNT=0x600)

# win32_stubs: stub functions for active-response executables (exported so
# active-response/CMakeLists.txt can reference WIN_STUBS directly)
add_library(win32_stubs OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/win_stubs.c)
target_compile_definitions(win32_stubs PRIVATE ARGV0="wazuh-agent"
                                               _WIN32_WINNT=0x600)

# win32_ui: UI source files compiled with ARGV0="wazuh-win32ui" and no OSSECHIDS
add_library(win32_ui OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/ui/os_win32ui.c
                            ${CMAKE_CURRENT_SOURCE_DIR}/ui/common.c)
target_compile_definitions(win32_ui PRIVATE ARGV0="wazuh-win32ui"
                                            _WIN32_WINNT=0x600)
target_include_directories(win32_ui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ui/
                                            ${SRC_FOLDER}/syscheckd/include/)

# ──────────────────────────────────────────────────────────────────────────────
# Executables (skip during unit tests)
# ──────────────────────────────────────────────────────────────────────────────
if(UNIT_TEST)
  return()
endif()

# --- wazuh-agent.exe ---
add_executable(
  wazuh-agent
  $<TARGET_OBJECTS:win32_common> ${CMAKE_CURRENT_SOURCE_DIR}/wazuh-agent.rc
  ${CMAKE_CURRENT_SOURCE_DIR}/icofile.rc ${RESOURCE_OBJ_APP})
target_compile_definitions(wazuh-agent PRIVATE OSSECHIDS ARGV0="wazuh-agent"
                                               _WIN32_WINNT=0x600)
set_target_properties(
  wazuh-agent PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/win32
                         OUTPUT_NAME wazuh-agent)
target_link_libraries(
  wazuh-agent
  PRIVATE dbsync
          wazuh-agentd
          wazuh-logcollector
          wazuh-execd
          wazuh-syscheckd
          fimdb
          agent_metadata
          agent_sync_protocol
          schema_validator
          config
          wazuh-modulesd
          wazuh
          ${WAZUHEXT_LIB}
          rootcheck
          ${WIN_SYSTEM_LIBS})

# --- wazuh-agent-eventchannel.exe ---
add_executable(
  wazuh-agent-eventchannel
  $<TARGET_OBJECTS:win32_common>
  ${CMAKE_CURRENT_SOURCE_DIR}/wazuh-agent-eventchannel.rc
  ${CMAKE_CURRENT_SOURCE_DIR}/icofile.rc ${RESOURCE_OBJ_APP})
target_compile_definitions(
  wazuh-agent-eventchannel PRIVATE OSSECHIDS ARGV0="wazuh-agent"
                                   EVENTCHANNEL_SUPPORT _WIN32_WINNT=0x600)
set_target_properties(
  wazuh-agent-eventchannel
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/win32
             OUTPUT_NAME wazuh-agent-eventchannel)
target_link_libraries(
  wazuh-agent-eventchannel
  PRIVATE dbsync
          wazuh-agentd
          wazuh-logcollector-event
          wazuh-execd
          wazuh-syscheckd-event
          fimdb
          agent_metadata
          agent_sync_protocol
          schema_validator
          config
          wazuh-modulesd
          wazuh
          ${WAZUHEXT_LIB}
          rootcheck
          ${WIN_SYSTEM_LIBS})

# --- setup-windows.exe ---
add_executable(
  setup-windows
  $<TARGET_OBJECTS:win32_service_rk> $<TARGET_OBJECTS:win32_setup>
  ${CMAKE_CURRENT_SOURCE_DIR}/setup-win.c)
target_compile_definitions(setup-windows PRIVATE ARGV0="setup-windows"
                                                 _WIN32_WINNT=0x600)
set_target_properties(
  setup-windows PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/win32
                           OUTPUT_NAME setup-windows)
target_link_libraries(setup-windows PRIVATE wazuh ${WAZUHEXT_LIB}
                                            ${WIN_SYSTEM_LIBS})

# --- setup-syscheck.exe ---
add_executable(
  setup-syscheck
  $<TARGET_OBJECTS:win32_service_rk> $<TARGET_OBJECTS:win32_setup>
  ${CMAKE_CURRENT_SOURCE_DIR}/setup-syscheck.c)
target_compile_definitions(setup-syscheck PRIVATE ARGV0="setup-syscheck"
                                                  _WIN32_WINNT=0x600)
set_target_properties(
  setup-syscheck PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/win32
                            OUTPUT_NAME setup-syscheck)
target_link_libraries(setup-syscheck PRIVATE wazuh ${WAZUHEXT_LIB}
                                             ${WIN_SYSTEM_LIBS})

# --- setup-iis.exe ---
add_executable(setup-iis $<TARGET_OBJECTS:win32_service_rk>
                         ${CMAKE_CURRENT_SOURCE_DIR}/setup-iis.c)
target_compile_definitions(setup-iis PRIVATE ARGV0="setup-iis"
                                             _WIN32_WINNT=0x600)
set_target_properties(
  setup-iis PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/win32 OUTPUT_NAME
                                                                    setup-iis)
target_link_libraries(setup-iis PRIVATE wazuh ${WAZUHEXT_LIB}
                                        ${WIN_SYSTEM_LIBS})

# --- os_win32ui.exe ---
add_executable(
  os_win32ui $<TARGET_OBJECTS:win32_service_rk> $<TARGET_OBJECTS:win32_ui>
             ${CMAKE_CURRENT_SOURCE_DIR}/ui/win32ui.rc ${RESOURCE_OBJ_APP})
target_compile_definitions(os_win32ui PRIVATE ARGV0="wazuh-win32ui"
                                              _WIN32_WINNT=0x600)
target_include_directories(os_win32ui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ui/
                                              ${SRC_FOLDER}/syscheckd/include/)
set_target_properties(
  os_win32ui PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/win32 OUTPUT_NAME
                                                                     os_win32ui)
target_link_options(os_win32ui PRIVATE -mwindows)
target_link_libraries(os_win32ui PRIVATE wazuh ${WAZUHEXT_LIB}
                                         ${WIN_SYSTEM_LIBS})
