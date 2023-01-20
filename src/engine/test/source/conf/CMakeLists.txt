add_executable(iconf_test
    iconf_test.cpp
)
target_link_libraries(iconf_test gtest_main conf::iconf)
gtest_discover_tests(iconf_test)
