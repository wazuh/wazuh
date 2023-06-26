add_executable(test_handler_test
  handlers_test.cpp
  session_test.cpp
)

target_include_directories(test_handler_test
  PRIVATE ${TEST_SOURCE_DIR}/common
)

target_link_libraries(test_handler_test gtest_main gmock_main api test_mocks schemf::mocks)
gtest_discover_tests(test_handler_test)

set(ASSETS_PATH_TEST "${CMAKE_CURRENT_SOURCE_DIR}/assets/")
target_compile_definitions(test_handler_test PRIVATE
  ASSETS_PATH_TEST="${ASSETS_PATH_TEST}"
)
