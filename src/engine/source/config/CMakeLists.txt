add_library(configuration STATIC
    src/config.cpp
)
target_include_directories(configuration
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)
target_link_libraries(configuration base)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(configuration_utest
    ${UNIT_SRC_DIR}/config_test.cpp
)
target_link_libraries(configuration_utest GTest::gtest_main configuration)
gtest_discover_tests(configuration_utest)

endif(ENGINE_BUILD_TEST)
