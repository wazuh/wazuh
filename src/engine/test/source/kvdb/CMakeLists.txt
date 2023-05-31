add_executable(kvdb_test
  ${TEST_SOURCE_DIR}/kvdb/kvdb_test.cpp
)

target_include_directories(kvdb_test
  PRIVATE
  ${TEST_SOURCE_DIR}/common
)

target_link_libraries(kvdb_test gtest_main kvdb base metrics)

gtest_discover_tests(kvdb_test)
