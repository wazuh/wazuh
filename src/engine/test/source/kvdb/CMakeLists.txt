
add_executable(kvdb_test
  ${TEST_SOURCE_DIR}/kvdb/kvdb_test.cpp
)

target_link_libraries(kvdb_test  kvdb gtest_main base)

#target_compile_options(kvdb_test PUBLIC -fsanitize=address)

#gtest_discover_tests(kvdb_test)
