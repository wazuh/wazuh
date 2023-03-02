# Configuration Catalog tests
add_executable(metrics_test
  ${TEST_SOURCE_DIR}/metrics/tracer_test.cpp
  ${TEST_SOURCE_DIR}/metrics/instrumentation_test.cpp
)

target_link_libraries(metrics_test metrics engine_test_main base)

gtest_discover_tests(metrics_test)
