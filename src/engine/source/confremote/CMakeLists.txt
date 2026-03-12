# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(confremote_iconfremote INTERFACE)
target_include_directories(confremote_iconfremote INTERFACE ${IFACE_DIR})
target_link_libraries(confremote_iconfremote INTERFACE base)
add_library(confremote::iconfremote ALIAS confremote_iconfremote)

# Implementation
add_library(confremote_confremote STATIC
    ${SRC_DIR}/confremotemanager.cpp
)
target_include_directories(confremote_confremote
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(confremote_confremote
    PUBLIC
    confremote::iconfremote
    wIndexerConnector::iwIndexerConnector
    store::istore
)
add_library(confremote::confremote ALIAS confremote_confremote)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

# Unit tests
add_executable(confremote_utest
    ${UNIT_SRC_DIR}/confremotemanager_test.cpp
)
target_link_libraries(confremote_utest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    conf
    confremote::confremote
    store::mocks
    wIndexerConnector::mocks
)
target_include_directories(confremote_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(confremote_utest)

# Component tests
add_executable(confremote_ctest
    ${COMPONENT_SRC_DIR}/confremote_refresh_test.cpp
)
target_link_libraries(confremote_ctest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    conf
    rawevtindexer::rawevtindexer
    confremote::confremote
    store::mocks
    wIndexerConnector::mocks
)
target_include_directories(confremote_ctest PRIVATE ${SRC_DIR})
gtest_discover_tests(confremote_ctest)

endif(ENGINE_BUILD_TEST)
