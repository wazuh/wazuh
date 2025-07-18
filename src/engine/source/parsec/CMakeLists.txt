# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(parsec INTERFACE)
target_include_directories(parsec INTERFACE ${IFACE_DIR})
target_link_libraries(parsec INTERFACE base)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)

add_executable(parsec_test
    ${TEST_SRC_DIR}/parsec_test.cpp
)
target_link_libraries(parsec_test parsec GTest::gtest_main GTest::gtest)
gtest_discover_tests(parsec_test)

endif(ENGINE_BUILD_TEST)
