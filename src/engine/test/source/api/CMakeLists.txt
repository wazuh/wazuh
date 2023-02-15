add_executable(api_test
    registry_test.cpp
)

target_link_libraries(api_test gtest_main base api)
gtest_discover_tests(api_test)

add_subdirectory(catalog)

add_subdirectory(kvdb)
