add_executable(api_test
    registry_test.cpp
)

target_link_libraries(api_test gtest_main base api)
gtest_discover_tests(api_test)

# Print warning to Cmake to not build these tests
message(WARNING "TODO These tests are not built, fix them and remove this warning")

# TODO
# add_subdirectory(catalog)
# add_subdirectory(kvdb)
