add_executable(kvdb_test
  ${TEST_SOURCE_DIR}/kvdb/kvdb_test.cpp
)

target_link_libraries(kvdb_test kvdb engine_test_main base)

gtest_discover_tests(kvdb_test)
