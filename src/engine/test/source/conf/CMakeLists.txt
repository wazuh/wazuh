add_executable(iconf_test
    iconf_test.cpp
)
target_link_libraries(iconf_test gtest_main conf::iconf)
gtest_discover_tests(iconf_test)

add_executable(conf_test
    conf_test.cpp
)
target_link_libraries(conf_test gtest_main conf::cliconf)
gtest_discover_tests(conf_test)
