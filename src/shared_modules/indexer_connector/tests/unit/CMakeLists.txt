cmake_minimum_required(VERSION 3.12.4)

project(indexer_connector_utest)

file(GLOB SOURCES *.cpp)

# These tests instantiate the connector Impl templates from src/ directly instead of linking
# libindexer_connector.so, so any non-template symbol those headers call has to be compiled in here
# too. buildSecureCommunication() lives in its own TU precisely so its credential cache is unique
# process-wide; keeping it out of the header is what makes `queue/keystore` open once.
add_executable(${PROJECT_NAME} ${SOURCES}
               ${CMAKE_CURRENT_LIST_DIR}/../../src/indexerTransport.cpp)

target_link_libraries(
  ${PROJECT_NAME}
  urlrequest
  debug
  gtestd
  debug
  gtest_maind
  debug
  gmockd
  debug
  gmock_maind
  optimized
  gtest
  optimized
  gtest_main
  optimized
  gmock
  optimized
  gmock_main
  keystore
  pthread
  simdjson)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS ${PROJECT_NAME})
