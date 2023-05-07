add_executable(kvdb2_test
  ${TEST_SOURCE_DIR}/kvdb2/kvdb2_test.cpp
)

target_include_directories(kvdb2_test
  PRIVATE
  ${TEST_SOURCE_DIR}/common
)

target_link_libraries(kvdb2_test gtest_main kvdb2 base metrics)

gtest_discover_tests(kvdb2_test)
