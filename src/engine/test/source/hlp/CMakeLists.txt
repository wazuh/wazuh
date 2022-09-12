# Configuration Catalog tests
add_executable(hlp_test
  ${TEST_SOURCE_DIR}/hlp/hlp_test.cpp
  ${TEST_SOURCE_DIR}/hlp/parserKVMap_test.cpp
  ${TEST_SOURCE_DIR}/hlp/parserIgnore_test.cpp
)

target_link_libraries(hlp_test hlp gtest_main)

gtest_discover_tests(hlp_test)
