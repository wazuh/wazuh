add_executable(cmds_test
    stackExecutor_test.cpp
)

target_include_directories(cmds_test
    PRIVATE
    ${ENGINE_SOURCE_DIR}/cmds/src
)

target_link_libraries(cmds_test gtest_main base cmds)
gtest_discover_tests(cmds_test)
