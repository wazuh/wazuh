add_executable(rxFactory_test
    ${CMAKE_CURRENT_LIST_DIR}/rxFactory_test.cpp
)
target_link_libraries(rxFactory_test gtest_main rxbk)
gtest_discover_tests(rxFactory_test)
