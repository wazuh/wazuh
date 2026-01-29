cmake_minimum_required(VERSION 3.12.4)

project(agent_metadata_tests)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/shared_modules/agent_metadata/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)
link_directories(${CMAKE_BINARY_DIR}/../lib/)

set(TEST_SOURCES main.cpp test_metadata_provider.cpp)

add_executable(agent_metadata_tests ${TEST_SOURCES})

target_include_directories(
  agent_metadata_tests
  PRIVATE ${SRC_FOLDER}/shared_modules/agent_metadata/include)

target_link_libraries(
  agent_metadata_tests
  PRIVATE agent_metadata
          debug
          gtestd
          debug
          gmockd
          optimized
          gtest
          optimized
          gmock
          pthread)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_custom_command(
    TARGET agent_metadata_tests
    POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy_if_different
      "${CMAKE_BINARY_DIR}/bin/libagent_metadata.dll"
      "$<TARGET_FILE_DIR:agent_metadata_tests>/libagent_metadata.dll"
    COMMENT "Copying libagent_metadata.dll to test directory")
else()
  # Create var/run directory for Unix shared memory file
  add_custom_command(
    TARGET agent_metadata_tests
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/bin/var/run"
    COMMENT "Creating var/run directory for shared memory")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME agent_metadata_tests COMMAND agent_metadata_tests)

set_tests_properties(agent_metadata_tests PROPERTIES LABELS "agent_metadata")
set_tests_properties(agent_metadata_tests PROPERTIES WORKING_DIRECTORY
                                                     "${CMAKE_BINARY_DIR}/bin")
