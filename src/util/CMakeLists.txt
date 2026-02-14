cmake_minimum_required(VERSION 3.12.4)

project(wazuh-util C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Skip building utilities during unit tests
if(UNIT_TEST)
  return()
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
  ${SRC_FOLDER}/logcollector/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_modules/src/task_manager/)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-DGROUPGLOBAL="wazuh")

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

# verify-agent-conf is a standalone executable
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_executable(verify-agent-conf
                 "${CMAKE_CURRENT_SOURCE_DIR}/src/verify-agent-conf.c")
  set_target_properties(
    verify-agent-conf PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY
                                                   ${SRC_FOLDER})
  target_link_libraries(verify-agent-conf PRIVATE config wazuh_modulesd_lib
                                                  wazuhext pthread wazuh)

  if(UNIX)
    target_link_libraries(verify-agent-conf PRIVATE dl)
    if(NOT APPLE)
      target_link_libraries(verify-agent-conf PRIVATE rt)
    endif(NOT APPLE)
  endif(UNIX)

  if(APPLE)
    set_target_properties(
      verify-agent-conf PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE
                                   INSTALL_RPATH "@executable_path/../lib")
  else()
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
  endif()
endif()
