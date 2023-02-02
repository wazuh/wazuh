# Configuration Catalog tests
add_executable(libLinking_test
  ${TEST_SOURCE_DIR}/metrics/libLinking_test.cpp
)

target_link_libraries(libLinking_test metrics engine_test_main base)

gtest_discover_tests(libLinking_test)
