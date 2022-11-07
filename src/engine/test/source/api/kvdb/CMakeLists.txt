add_executable(kvdb_commands_test
  commands_test.cpp
)

target_link_libraries(kvdb_commands_test gtest_main api kvdb)
gtest_discover_tests(kvdb_commands_test)
