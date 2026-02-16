cmake_minimum_required(VERSION 3.12.4)

project(wazuh-execd C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/shared/os_net/
  ${SRC_FOLDER}/shared/os_regex/
  ${SRC_FOLDER}/shared/os_xml/
  ${SRC_FOLDER}/shared/os_crypto/sha1/
  ${SRC_FOLDER}/shared/os_crypto/signature/
  ${SRC_FOLDER}/shared/error_messages/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/libyaml/include/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/openssl/include/
  ${SRC_FOLDER}/external/zlib/
  ${SRC_FOLDER}/config/include/
  ${SRC_FOLDER}/client-agent/include/
  ${SRC_FOLDER}/logcollector/include/
  ${SRC_FOLDER}/rootcheck/include/
  ${SRC_FOLDER}/active-response/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_modules/src/task_manager/
  ${CMAKE_CURRENT_SOURCE_DIR}/include/)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Keep agent daemon name for agent/winagent targets and manager daemon name for
# server/local/hybrid targets.
set(WAZUH_EXECD_DAEMON_NAME "wazuh-execd")
set(WAZUH_RUNTIME_GROUP "wazuh")
if(NOT "${TARGET}" STREQUAL "winagent" AND NOT "${TARGET}" STREQUAL "agent")
  set(WAZUH_EXECD_DAEMON_NAME "wazuh-manager-execd")
  set(WAZUH_RUNTIME_GROUP "wazuh-manager")
endif()
add_definitions(-DARGV0="${WAZUH_EXECD_DAEMON_NAME}")
add_definitions(-DGROUPGLOBAL="${WAZUH_RUNTIME_GROUP}")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

# Collect source files
file(GLOB EXECD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Build static library (without main.c) for unit tests and Windows agent
list(REMOVE_ITEM EXECD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
add_library(execd_lib STATIC ${EXECD_SRC})
set_target_properties(execd_lib PROPERTIES LINKER_LANGUAGE C)

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(execd_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_definitions(execd_lib PRIVATE _FORTIFY_SOURCE=0)
  target_compile_options(execd_lib PRIVATE -O0 -g)
endif()

target_link_libraries(execd_lib PUBLIC wazuhext pthread config
                                       wazuh_modulesd_lib wazuh)

if(UNIX)
  target_link_libraries(execd_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(execd_lib PUBLIC rt)
  endif(NOT APPLE)
endif(UNIX)

# Build Windows libraries (needed by Makefile for final win32 executables)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(wazuh-execd STATIC ${EXECD_SRC})
  target_compile_definitions(wazuh-execd PUBLIC -D_WIN32_WINNT=0x600)
  if(UNIT_TEST)
    target_compile_definitions(wazuh-execd PRIVATE WAZUH_UNIT_TESTING)
  endif()
  target_link_libraries(wazuh-execd PRIVATE wazuhext pthread config
                                            wazuh_modulesd_lib wazuh)
  # Only build Unix executable when not running unit tests
elseif(NOT UNIT_TEST)
  add_executable(${WAZUH_EXECD_DAEMON_NAME}
                 "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
  set_target_properties(
    ${WAZUH_EXECD_DAEMON_NAME}
    PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER})
  target_link_libraries(${WAZUH_EXECD_DAEMON_NAME} PRIVATE execd_lib)

  if(APPLE)
    set_target_properties(
      ${WAZUH_EXECD_DAEMON_NAME} PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE
                                             INSTALL_RPATH
                                             "@executable_path/../lib")
  else()
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
  endif()
endif()
