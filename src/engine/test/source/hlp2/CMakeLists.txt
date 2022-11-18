add_executable(parsec_test
    parsec_test.cpp
)
target_link_libraries(parsec_test hlp::parsec gtest_main)
gtest_discover_tests(parsec_test)
