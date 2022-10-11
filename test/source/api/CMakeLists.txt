add_executable(api_test
    registry_test.cpp
    wazuhRequest_test.cpp
    wazuhResponse_test.cpp
)

target_link_libraries(api_test gtest_main base api)
gtest_discover_tests(api_test)
