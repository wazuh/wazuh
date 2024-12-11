add_library(conf STATIC
    src/conf.cpp
    src/apiLoader.cpp
)
target_include_directories(conf
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)
target_link_libraries(conf
    PUBLIC
    base
    PRIVATE
    urlrequest
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(conf_utest
    ${UNIT_SRC_DIR}/conf_test.cpp
    ${UNIT_SRC_DIR}/unitconf_test.cpp
)
target_link_libraries(conf_utest GTest::gtest_main GTest::gmock conf)
gtest_discover_tests(conf_utest)

add_executable(conf_ctest
    ${COMPONENT_SRC_DIR}/apiLoader_test.cpp
)

target_link_libraries(conf_ctest PRIVATE conf GTest::gtest_main apiserver)
gtest_discover_tests(conf_ctest)

endif(ENGINE_BUILD_TEST)
