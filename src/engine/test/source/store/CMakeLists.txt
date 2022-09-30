add_executable(store_test
  shared_test.cpp
  drivers/fileDriver/fileDriver_test.cpp
)

target_link_libraries(store_test gtest_main store_fileDriver base)
gtest_discover_tests(store_test)
