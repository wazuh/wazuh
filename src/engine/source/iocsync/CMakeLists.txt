# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR   ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(iocsync_iiocsync INTERFACE)
target_include_directories(iocsync_iiocsync INTERFACE ${IFACE_DIR})
target_link_libraries(iocsync_iiocsync INTERFACE base)
add_library(iocsync::iiocsync ALIAS iocsync_iiocsync)

# Implementation
add_library(iocsync_iocsync STATIC
    ${SRC_DIR}/iocsync.cpp
)
target_include_directories(iocsync_iocsync
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(iocsync_iocsync
    PUBLIC
    iocsync::iiocsync
    PRIVATE
    wIndexerConnector::iwIndexerConnector
    store::istore
    iockvdb::ikvdb
)
add_library(iocsync::iocsync ALIAS iocsync_iocsync)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR   ${TEST_SRC_DIR}/unit)

# Unit tests
add_executable(iocsync_utest
    ${UNIT_SRC_DIR}/iocsync_status_test.cpp
)
target_link_libraries(iocsync_utest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        iocsync::iocsync
        store::mocks
        wIndexerConnector::mocks
        iockvdb::mocks
)
target_include_directories(iocsync_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(iocsync_utest)

endif(ENGINE_BUILD_TEST)

# iocsync mocks (available for other modules' tests)
if(ENGINE_BUILD_TEST)
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
    add_library(iocsync_mocks INTERFACE)
    target_include_directories(iocsync_mocks INTERFACE ${TEST_MOCK_DIR})
    target_link_libraries(iocsync_mocks INTERFACE GTest::gmock iocsync::iiocsync)
    add_library(iocsync::mocks ALIAS iocsync_mocks)
endif()
