cmake_minimum_required(VERSION 3.12.4)

project(wazuh-utils C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Manager-only, Linux-only. Skipped under UNIT_TEST: the test target builds
# this same source itself, with its own compile definitions (see
# src/unit_tests/utils/CMakeLists.txt).
if(WAZUH_MAIN_PROJECT AND NOT IS_AGENT AND CMAKE_SYSTEM_NAME STREQUAL "Linux"
   AND NOT UNIT_TEST)
  add_executable(wazuh-manager-service-control
                 "${CMAKE_CURRENT_SOURCE_DIR}/manager_service_control/main.c")
  target_compile_definitions(
    wazuh-manager-service-control PRIVATE WAZUH_RUNTIME_USER="wazuh-manager")
  set_target_properties(
    wazuh-manager-service-control
    PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY
                                 ${SRC_FOLDER}/build/bin)
endif()
