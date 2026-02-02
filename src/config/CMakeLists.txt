cmake_minimum_required(VERSION 3.12.4)

project(config C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SRC_FOLDER}/headers/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/os_crypto/md5_sha1_sha256
  ${SRC_FOLDER}/os_regex
  ${SRC_FOLDER}/os_net
  ${SRC_FOLDER}/os_xml
  ${SRC_FOLDER}/wazuh_modules/include
  ${SRC_FOLDER}/wazuh_modules/src
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager
  ${SRC_FOLDER}/wazuh_modules/src/task_manager
  ${SRC_FOLDER}/wazuh_db)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

# Collect config source files - split into core and wmodules
file(GLOB CONFIG_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

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
