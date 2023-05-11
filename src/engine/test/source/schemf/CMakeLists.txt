add_executable(schema_test schema_test.cpp)
target_link_libraries(schema_test gtest_main schemf)
gtest_discover_tests(schema_test)

add_executable(field_test field_test.cpp)
target_link_libraries(field_test gtest_main schemf)
# gtest_discover_tests(field_test)
