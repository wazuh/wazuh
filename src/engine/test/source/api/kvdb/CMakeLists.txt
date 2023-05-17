add_executable(kvdb_handler_test
  kvdb_api_test.cpp
)

target_include_directories(kvdb_handler_test
  PRIVATE ${TEST_SOURCE_DIR}/common
)

target_link_libraries(kvdb_handler_test gtest_main api kvdb2)
gtest_discover_tests(kvdb_handler_test)
