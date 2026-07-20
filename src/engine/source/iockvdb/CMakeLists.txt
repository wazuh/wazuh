# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR   ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(iockvdb_ikvdb INTERFACE)
target_include_directories(iockvdb_ikvdb INTERFACE ${IFACE_DIR})
target_link_libraries(iockvdb_ikvdb INTERFACE base)
add_library(iockvdb::ikvdb ALIAS iockvdb_ikvdb)

# Implementation
add_library(iockvdb_kvdb STATIC
    ${SRC_DIR}/manager.cpp
    ${SRC_DIR}/dbInstance.cpp
    ${SRC_DIR}/dbHandle.cpp
)
target_include_directories(iockvdb_kvdb
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(iockvdb_kvdb
    PUBLIC
    iockvdb::ikvdb
    PRIVATE
    rocksdb
    store::istore
)
add_library(iockvdb::kvdb ALIAS iockvdb_kvdb)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR   ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR  ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(iockvdb_mocks INTERFACE)
target_include_directories(iockvdb_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(iockvdb_mocks INTERFACE GTest::gmock iockvdb::ikvdb)
add_library(iockvdb::mocks ALIAS iockvdb_mocks)

# Unit tests
add_executable(iockvdb_utest
    ${UNIT_SRC_DIR}/kvdb_handler_test.cpp
    ${UNIT_SRC_DIR}/kvdb_manager_test.cpp
)
target_link_libraries(iockvdb_utest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        iockvdb::kvdb
        iockvdb::mocks
)
target_include_directories(iockvdb_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(iockvdb_utest)

# Component tests
add_executable(iockvdb_ctest
    ${COMPONENT_SRC_DIR}/kvdb_test.cpp
)
target_link_libraries(iockvdb_ctest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        iockvdb::kvdb
        store::mocks
)
gtest_discover_tests(iockvdb_ctest)

endif(ENGINE_BUILD_TEST)
