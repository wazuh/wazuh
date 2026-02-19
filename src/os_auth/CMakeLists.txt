cmake_minimum_required(VERSION 3.12.4)

project(wazuh-authd C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/shared/os_net/
  ${SRC_FOLDER}/shared/os_regex/
  ${SRC_FOLDER}/shared/os_xml/
  ${SRC_FOLDER}/shared/os_crypto/md5/
  ${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256/
  ${SRC_FOLDER}/shared/os_crypto/sha1/
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
  ${SRC_FOLDER}/syscheckd/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_modules/src/task_manager/
  ${SRC_FOLDER}/wazuh_db/include/
  ${CMAKE_CURRENT_SOURCE_DIR}/include/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(WAZUH_RUNTIME_GROUP "wazuh")
if(NOT "${TARGET}" STREQUAL "winagent" AND NOT "${TARGET}" STREQUAL "agent")
  set(WAZUH_RUNTIME_GROUP "wazuh-manager")
endif()

add_definitions(-DARGV0="wazuh-manager-authd")
add_definitions(-DGROUPGLOBAL="${WAZUH_RUNTIME_GROUP}")

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

# Collect source files
file(GLOB AUTHD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Build static library (without main-server.c) for unit tests
list(REMOVE_ITEM AUTHD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main-server.c")
add_library(authd_lib STATIC ${AUTHD_SRC})
set_target_properties(authd_lib PROPERTIES LINKER_LANGUAGE C)

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(authd_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_options(authd_lib PRIVATE -O0 -g)
endif()

target_link_libraries(authd_lib PUBLIC wazuhext pthread router config
                                       wazuh_modulesd_lib wazuh)

if(UNIX)
  target_link_libraries(authd_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(authd_lib PUBLIC rt)
  endif(NOT APPLE)
endif(UNIX)

# Only build Unix executable when not running unit tests (server-only, no
# Windows)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT UNIT_TEST)
  add_executable(wazuh-manager-authd
                 "${CMAKE_CURRENT_SOURCE_DIR}/src/main-server.c")
  set_target_properties(
    wazuh-manager-authd PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY
                                                     ${SRC_FOLDER})
  target_link_libraries(wazuh-manager-authd PRIVATE authd_lib)

  if(APPLE)
    set_target_properties(
      wazuh-manager-authd PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE
                                     INSTALL_RPATH "@executable_path/../lib")
  else()
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
  endif()
endif()
