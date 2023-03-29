
add_executable(cmds_test
    stackExecutor_test.cpp
)

target_include_directories(cmds_test
    PRIVATE
    ${ENGINE_SOURCE_DIR}/cmds/src
    ${TEST_SOURCE_DIR}/base/utils/tests
)

target_link_libraries(cmds_test gtest_main base cmds)
gtest_discover_tests(cmds_test)

add_executable(cli11_test
    cli11_test.cpp
)
target_include_directories(cli11_test
    PUBLIC
    ${CLI11_SOURCE_DIR}/include
)
target_link_libraries(cli11_test gtest_main )
gtest_discover_tests(cli11_test)
