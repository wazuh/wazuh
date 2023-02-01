add_executable(cliconf_test
cliconf_test.cpp
)
target_link_libraries(cliconf_test gtest_main conf::cliconf)
gtest_discover_tests(cliconf_test)
