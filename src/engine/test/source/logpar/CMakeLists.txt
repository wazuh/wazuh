add_executable(parsec_test
    parsec_test.cpp
)
target_link_libraries(parsec_test logpar gtest_main)
gtest_discover_tests(parsec_test)

add_executable(logpar_test
    logpar_test.cpp
)
target_link_libraries(logpar_test logpar gtest_main)
gtest_discover_tests(logpar_test)
