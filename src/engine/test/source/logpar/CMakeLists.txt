add_executable(logpar_test
    logpar_test.cpp
)
target_link_libraries(logpar_test logpar gtest_main schemf::mocks)
gtest_discover_tests(logpar_test)
