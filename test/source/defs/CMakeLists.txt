add_executable(defs_test defs_test.cpp)
target_link_libraries(defs_test gtest_main defs)
gtest_discover_tests(defs_test)
