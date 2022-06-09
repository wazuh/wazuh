add_executable(server_tests
    protocolHandler_test.cpp
)

target_include_directories(server_tests
    PRIVATE
    ${ENGINE_SOURCE_DIR}/server/
    ${TEST_SOURCE_DIR}/server/
    ${ENGINE_SOURCE_DIR}/json
    ${rapidjson_SOURCE_DIR}/include
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

target_link_libraries(server_tests gtest engine_test_main server)
gtest_discover_tests(server_tests)
