add_executable(store_test
  drivers/fileDriver/fileDriver_test.cpp
)

target_link_libraries(store_test gtest_main store::fileDriver)
gtest_discover_tests(store_test)
