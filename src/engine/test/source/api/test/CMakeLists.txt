add_executable(test_handler_test
  #handlers_test.cpp
  handlers_without_files_test.cpp
)

target_include_directories(test_handler_test
  PRIVATE ${TEST_SOURCE_DIR}/common
  ${TEST_SOURCE_DIR}/api/test/internal/router_table
)

target_link_libraries(test_handler_test gtest_main gmock_main api test_mocks schemf::mocks)
gtest_discover_tests(test_handler_test)
