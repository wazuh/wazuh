cmake_minimum_required(VERSION 3.12.4)

project(inventory_sync_server_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)

file(GLOB UNIT_SRC_FILES ${UNIT_SRC_DIR}/*.cpp)

add_executable(inventory_sync_server_utest ${UNIT_SRC_FILES})

target_link_libraries(
  inventory_sync_server_utest
  debug gtestd
  debug gmockd
  debug gtest_maind
  debug gmock_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  optimized gmock_main
  # Linking the .so is the only way a test can observe what the module logs: its
  # Log::GLOBAL_LOG_FUNCTION has hidden visibility, so a definition in this binary would be a
  # different object entirely.
  inventory_sync_server
  pthread
  # inventorySyncServerModule_test.cpp builds a real cJSON tree to exercise the C-ABI's borrow
  # contract; wazuhext is where cJSON lives (see the module's CMakeLists.txt).
  wazuhext
  # indexerGating_test.cpp's file-local fake connectors implement IIndexerConnector directly and
  # need no indexer_connector symbols themselves, but inventorySyncServerModule_test.cpp's default
  # (unmocked) startup path resolves into the real IndexerConnectorSync inside the linked .so.
  indexer_connector)

target_include_directories(
  inventory_sync_server_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
          ${CMAKE_CURRENT_LIST_DIR}/../src # submodule headers by prefix: http_server/, endpoints/, common/
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp, proc.hpp
          ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/external/cJSON
          ${SRC_FOLDER}/external/nlohmann
          # The server tests drive a raw UDS client with standalone Asio directly, and the parser
          # test includes llhttp. inventory_sync_server links both PRIVATE, so neither propagates
          # to this target.
          ${SRC_FOLDER}/external/asio/include
          ${SRC_FOLDER}/external/llhttp/include
          # vulnerabilityScannerSync.hpp: the NEUTRAL coordination header the coordinator tests
          # exercise -- never the scanner's facade.
          ${SRC_FOLDER}/wazuh_modules/vulnerability_scanner/include)

target_compile_definitions(inventory_sync_server_utest PRIVATE ASIO_STANDALONE)

add_test(NAME inventory_sync_server_utest COMMAND inventory_sync_server_utest)
set_tests_properties(inventory_sync_server_utest PROPERTIES LABELS inventory_sync_server_utest)
