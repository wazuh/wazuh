# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR   ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(kvdbioc_ikvdb INTERFACE)
target_include_directories(kvdbioc_ikvdb INTERFACE ${IFACE_DIR})
target_link_libraries(kvdbioc_ikvdb INTERFACE base)
add_library(kvdbioc::ikvdb ALIAS kvdbioc_ikvdb)

# Implementation
add_library(kvdbioc_kvdb STATIC
    ${SRC_DIR}/manager.cpp
    ${SRC_DIR}/dbInstance.cpp
    ${SRC_DIR}/dbHandle.cpp
)
target_include_directories(kvdbioc_kvdb
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(kvdbioc_kvdb
    PUBLIC
    kvdbioc::ikvdb
    PRIVATE
    rocksdb
    store::istore
)
add_library(kvdbioc::kvdb ALIAS kvdbioc_kvdb)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR   ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR  ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(kvdbioc_mocks INTERFACE)
target_include_directories(kvdbioc_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(kvdbioc_mocks INTERFACE GTest::gmock kvdbioc::ikvdb)
add_library(kvdbioc::mocks ALIAS kvdbioc_mocks)

# Unit tests
add_executable(kvdbioc_utest
    ${UNIT_SRC_DIR}/kvdb_handler_test.cpp
    ${UNIT_SRC_DIR}/kvdb_manager_test.cpp
)
target_link_libraries(kvdbioc_utest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        kvdbioc::kvdb
        kvdbioc::mocks
)
target_include_directories(kvdbioc_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(kvdbioc_utest)

# Component tests
add_executable(kvdbioc_ctest
    ${COMPONENT_SRC_DIR}/kvdb_test.cpp
)
target_link_libraries(kvdbioc_ctest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        kvdbioc::kvdb
        store::mocks
)
gtest_discover_tests(kvdbioc_ctest)

endif(ENGINE_BUILD_TEST)
