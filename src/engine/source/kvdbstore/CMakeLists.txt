# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR   ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(kvdbstore_ikvdb INTERFACE)
target_include_directories(kvdbstore_ikvdb INTERFACE ${IFACE_DIR})
target_link_libraries(kvdbstore_ikvdb INTERFACE base)
add_library(kvdbstore::ikvdb ALIAS kvdbstore_ikvdb)

# Implementation
add_library(kvdbstore_kvdb STATIC
    ${SRC_DIR}/kvdbManager.cpp
    ${SRC_DIR}/kvdbHandler.cpp
)
target_include_directories(kvdbstore_kvdb
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(kvdbstore_kvdb
    PUBLIC
    kvdbstore::ikvdb
    base
    cmstore::icmstore
)
add_library(kvdbstore::kvdb ALIAS kvdbstore_kvdb)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR   ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR  ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(kvdbstore_mocks INTERFACE)
target_include_directories(kvdbstore_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(kvdbstore_mocks INTERFACE GTest::gmock kvdbstore::ikvdb)
add_library(kvdbstore::mocks ALIAS kvdbstore_mocks)

# Unit tests
add_executable(kvdbstore_utest
    ${UNIT_SRC_DIR}/kvdb_handler_test.cpp
    ${UNIT_SRC_DIR}/kvdb_manager_test.cpp
)
target_link_libraries(kvdbstore_utest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        kvdbstore::kvdb
        kvdbstore::mocks
)
target_include_directories(kvdbstore_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(kvdbstore_utest)

# Component tests
add_executable(kvdbstore_ctest
    ${COMPONENT_SRC_DIR}/kvdb_test.cpp
)
target_link_libraries(kvdbstore_ctest
    PRIVATE
        GTest::gtest_main
        kvdbstore::kvdb
)
gtest_discover_tests(kvdbstore_ctest)

endif(ENGINE_BUILD_TEST)
