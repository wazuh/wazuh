add_library(conf STATIC
    src/conf.cpp
)
target_include_directories(conf
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)
target_link_libraries(conf base)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(conf_utest
    ${UNIT_SRC_DIR}/conf_test.cpp
)
target_link_libraries(conf_utest GTest::gtest_main conf)
gtest_discover_tests(conf_utest)

endif(ENGINE_BUILD_TEST)
