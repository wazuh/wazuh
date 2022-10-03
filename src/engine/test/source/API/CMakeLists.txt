add_executable(API_test
    registry_test.cpp
    wazuhRequest_test.cpp
    wazuhResponse_test.cpp
)

target_include_directories(API_test
    PRIVATE
    ${ENGINE_SOURCE_DIR}/API/src
)

target_link_libraries(API_test gtest_main base api)
gtest_discover_tests(API_test)
