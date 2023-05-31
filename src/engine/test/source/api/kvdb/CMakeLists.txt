add_executable(kvdb_api_test
  kvdb_api_test.cpp
)

target_include_directories(kvdb_api_test
  PRIVATE ${TEST_SOURCE_DIR}/common
)

target_link_libraries(kvdb_api_test gtest_main api kvdb)
gtest_discover_tests(kvdb_api_test)
