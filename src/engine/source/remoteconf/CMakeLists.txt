# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(remoteconf_iremoteconf INTERFACE)
target_include_directories(remoteconf_iremoteconf INTERFACE ${IFACE_DIR})
target_link_libraries(remoteconf_iremoteconf INTERFACE base)
add_library(remoteconf::iremoteconf ALIAS remoteconf_iremoteconf)

# Implementation
add_library(remoteconf_remoteconf STATIC
    ${SRC_DIR}/remoteconfmanager.cpp
)
target_include_directories(remoteconf_remoteconf
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(remoteconf_remoteconf
    PUBLIC
    remoteconf::iremoteconf
    wIndexerConnector::iwIndexerConnector
    store::istore
)
add_library(remoteconf::remoteconf ALIAS remoteconf_remoteconf)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

# Unit tests
add_executable(remoteconf_utest
    ${UNIT_SRC_DIR}/remoteconfmanager_test.cpp
)
target_link_libraries(remoteconf_utest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    conf
    remoteconf::remoteconf
    store::mocks
    wIndexerConnector::mocks
)
target_include_directories(remoteconf_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(remoteconf_utest)

# Component tests
add_executable(remoteconf_ctest
    ${COMPONENT_SRC_DIR}/remoteconf_refresh_test.cpp
)
target_link_libraries(remoteconf_ctest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    conf
    remoteconf::remoteconf
    store::mocks
    wIndexerConnector::mocks
)
target_include_directories(remoteconf_ctest PRIVATE ${SRC_DIR})
gtest_discover_tests(remoteconf_ctest)

endif(ENGINE_BUILD_TEST)
