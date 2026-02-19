cmake_minimum_required(VERSION 3.12.4)

project(config C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/libyaml/include
  ${SRC_FOLDER}/external/libplist/bin/include/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/shared/error_messages
  ${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256
  ${SRC_FOLDER}/shared/os_crypto/sha1
  ${SRC_FOLDER}/shared/os_regex
  ${SRC_FOLDER}/shared/os_net
  ${SRC_FOLDER}/shared/os_xml
  ${SRC_FOLDER}/shared_modules/dbsync/include
  ${SRC_FOLDER}/syscheckd/include
  ${SRC_FOLDER}/wazuh_modules/include
  ${SRC_FOLDER}/wazuh_modules/src
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager
  ${SRC_FOLDER}/wazuh_modules/src/task_manager
  ${SRC_FOLDER}/wazuh_db/include)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

# Collect config source files
file(GLOB CONFIG_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Remove agent-only config modules from server builds
if(NOT "${TARGET}" STREQUAL "winagent" AND NOT "${TARGET}" STREQUAL "agent")
  list(REMOVE_ITEM CONFIG_CORE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/wmodules-sca.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/wmodules-syscollector.c")
endif()

# Create config library
add_library(config STATIC ${CONFIG_CORE_SRC})

set_target_properties(
  config PROPERTIES LINKER_LANGUAGE C ARCHIVE_OUTPUT_DIRECTORY
                                      ${CMAKE_BINARY_DIR}/lib)

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(config PRIVATE WAZUH_UNIT_TESTING)
endif()

target_link_libraries(config PUBLIC wazuhext wazuh wazuh_modulesd_lib)
