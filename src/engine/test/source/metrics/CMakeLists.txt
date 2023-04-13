# Configuration Metrics tests
add_executable(metrics_test
  ${TEST_SOURCE_DIR}/metrics/interface_test.cpp
)

target_include_directories(metrics_test PRIVATE
  PRIVATE
  ${TEST_SOURCE_DIR}/common
)

target_link_libraries(metrics_test gtest_main metrics base)

gtest_discover_tests(metrics_test)
