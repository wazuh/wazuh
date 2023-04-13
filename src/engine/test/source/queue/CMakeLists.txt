# Queue Test
add_executable(queue_test
  ${TEST_SOURCE_DIR}/queue/queue_test.cpp
)

target_include_directories(queue_test PRIVATE
  ${TEST_SOURCE_DIR}/common
)

target_link_libraries(queue_test gtest_main queue test_mocks)
gtest_discover_tests(queue_test)
