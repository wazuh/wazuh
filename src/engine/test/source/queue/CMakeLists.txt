# Queue Test
add_executable(queue_test
  ${TEST_SOURCE_DIR}/queue/queue_test.cpp
)

target_link_libraries(queue_test engine_test_main queue)
gtest_discover_tests(queue_test)
