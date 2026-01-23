cmake_minimum_required(VERSION 3.12.4)

project(agent_sync_protocol_tests)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

message(STATUS "SRC_FOLDER is: ${SRC_FOLDER}")

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/flatbuffers/include/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/shared_modules/agent_metadata/include/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER})

link_directories(${SRC_FOLDER}/external/googletest/lib/)
link_directories(${CMAKE_BINARY_DIR}/lib/)

# Prepare test sources
set(TEST_SOURCES
    main.cpp test_persistent_queue_storage.cpp test_persistent_queue.cpp
    test_agent_sync_protocol_datacontext.cpp test_sync_protocol_integration.cpp)

# Add Router-specific tests only for SERVER builds
if(DEFINED ENV{TARGET} AND "$ENV{TARGET}" STREQUAL "server")
  list(APPEND TEST_SOURCES test_agent_sync_protocol_router.cpp)
  list(APPEND TEST_SOURCES test_router_transport.cpp)
else()
  list(APPEND TEST_SOURCES test_agent_sync_protocol.cpp)
  list(APPEND TEST_SOURCES test_mqueue_transport.cpp)
endif()

# Add the test executable
add_executable(agent_sync_protocol_tests ${TEST_SOURCES})

# Include paths
target_include_directories(
  agent_sync_protocol_tests
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
          ${CMAKE_CURRENT_SOURCE_DIR}/../src
          ${CMAKE_CURRENT_BINARY_DIR}/..
          ${CMAKE_CURRENT_SOURCE_DIR}/../../file_helper/filesystem/tests/mocks
          ${CMAKE_CURRENT_SOURCE_DIR}/../../file_helper/filesystem/include)

# Add router includes for SERVER builds
if(DEFINED ENV{TARGET} AND "$ENV{TARGET}" STREQUAL "server")
  target_include_directories(
    agent_sync_protocol_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../router/include)
endif()

target_link_libraries(
  agent_sync_protocol_tests
  PRIVATE agent_sync_protocol
          agent_metadata
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
    TARGET agent_sync_protocol_tests
    POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy_if_different
      "${CMAKE_BINARY_DIR}/bin/libagent_sync_protocol.dll"
      "$<TARGET_FILE_DIR:agent_sync_protocol_tests>/libagent_sync_protocol.dll"
    COMMENT "Copying libagent_sync_protocol.dll to test directory")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME agent_sync_protocol_tests COMMAND agent_sync_protocol_tests)
