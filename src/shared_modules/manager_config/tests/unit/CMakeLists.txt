cmake_minimum_required(VERSION 3.12.4)

project(manager_config_utest)

file(GLOB SOURCES *.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

target_compile_definitions(${PROJECT_NAME} PRIVATE
  MANAGER_CONFIG_TEST_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/../vectors")

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src
                                                   ${CMAKE_CURRENT_BINARY_DIR}/../../generated)

target_link_libraries(
  ${PROJECT_NAME}
  debug gtestd
  debug gtest_maind
  optimized gtest
  optimized gtest_main
  manager_config
  ext_rapidjson
  pthread)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS ${PROJECT_NAME})

# End-to-end: the CLI (bin/wazuh-manager-conf) over the vectors and over the file the installer
# generates (src/init/gen_wazuh.sh, WriteManager twin).
add_test(NAME manager_config_cli
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/../cli/manager_conf_cli_test.sh
                 $<TARGET_FILE:wazuh-manager-conf>
                 ${CMAKE_CURRENT_SOURCE_DIR}/../vectors
                 ${SRC_FOLDER}/..)

# Parity with the Python validator (jsonschema Draft4) over the same vectors, when a venv is available.
find_program(MANAGER_CONFIG_PYTHON NAMES python3 HINTS $ENV{TMP_PY_VENV}/bin NO_DEFAULT_PATH)
if(MANAGER_CONFIG_PYTHON)
  add_test(NAME manager_config_parity
           COMMAND ${MANAGER_CONFIG_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/../parity.py
                   ${CMAKE_CURRENT_SOURCE_DIR}/../../schema/wazuh-manager.schema.json
                   ${CMAKE_CURRENT_SOURCE_DIR}/../vectors)
endif()
