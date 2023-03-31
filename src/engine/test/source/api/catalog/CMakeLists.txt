add_executable(catalog_test
  catalog_test.cpp
  handlers_test.cpp
  resource_test.cpp
)

target_include_directories(catalog_test
  PRIVATE ${TEST_SOURCE_DIR}/common
)

target_link_libraries(catalog_test gtest_main api)
gtest_discover_tests(catalog_test)
