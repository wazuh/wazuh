add_executable(catalog_test
  catalog_test.cpp
  command_test.cpp
)

target_link_libraries(catalog_test gtest_main catalog)
gtest_discover_tests(catalog_test)
