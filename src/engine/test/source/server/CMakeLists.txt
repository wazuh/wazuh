add_executable(server_tests
    engineServer_test.cpp
    unixDatagram_test.cpp
    unixStream_test.cpp
    protocolHandlerStream_test.cpp
)

target_include_directories(server_tests
    PRIVATE
    ${uvw_SOURCE_DIR}/src/
)

target_link_libraries(server_tests gtest engine_test_main server uv_a)
gtest_discover_tests(server_tests)
