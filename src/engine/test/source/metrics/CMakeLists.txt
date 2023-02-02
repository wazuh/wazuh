# Configuration Catalog tests
add_executable(libLinking_test
  ${TEST_SOURCE_DIR}/metrics/libLinking_test.cpp
)

target_link_libraries(libLinking_test metrics gtest_main)

gtest_discover_tests(libLinking_test)
OPENTELEMETRYCPP