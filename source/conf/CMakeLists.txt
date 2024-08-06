add_library(conf_iconf INTERFACE)
target_include_directories(conf_iconf INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
add_library(conf::iconf ALIAS conf_iconf)

add_library(conf_cliconf STATIC
    src/cliconf.cpp
)
target_include_directories(conf_cliconf
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)
target_link_libraries(conf_cliconf base)
add_library(conf::cliconf ALIAS conf_cliconf)

add_library(conf INTERFACE)
target_link_directories(conf INTERFACE conf::iconf conf::cliconf)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(cliconf_utest
    ${UNIT_SRC_DIR}/cliconf_test.cpp
)
target_link_libraries(cliconf_utest GTest::gtest_main conf::cliconf CLI11::CLI11)
gtest_discover_tests(cliconf_utest)

endif(ENGINE_BUILD_TEST)
