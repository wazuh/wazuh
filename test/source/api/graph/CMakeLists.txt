add_executable(graph_handler_test
  handlers_test.cpp
)

target_include_directories(graph_handler_test
  PRIVATE ${TEST_SOURCE_DIR}/common
  ${TEST_SOURCE_DIR}/api/graph/assets/policy/wazuh
  ${TEST_SOURCE_DIR}/api/graph/assets/schema/wazuh-logpar-types
  ${TEST_SOURCE_DIR}/api/graph/assets/integration/wazuh-core
  ${TEST_SOURCE_DIR}/api/graph/assets/decoder/core-hostinfo
  ${TEST_SOURCE_DIR}/api/graph/assets/filter/allow-all
)

target_link_libraries(graph_handler_test gtest_main api)
gtest_discover_tests(graph_handler_test)
