add_executable(test_handler_test
  handlers_test.cpp
)

target_include_directories(test_handler_test
  PRIVATE ${TEST_SOURCE_DIR}/common
)

target_link_libraries(test_handler_test gtest_main gmock_main api test_mocks schemf::mocks)
gtest_discover_tests(test_handler_test)
