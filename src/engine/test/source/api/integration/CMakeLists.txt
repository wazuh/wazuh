add_executable(integration_test
  integration_test.cpp
  handlers_test.cpp
)

target_include_directories(integration_test PRIVATE
  ${TEST_SOURCE_DIR}/common
)

target_link_libraries(integration_test gtest_main api)
gtest_discover_tests(integration_test)
