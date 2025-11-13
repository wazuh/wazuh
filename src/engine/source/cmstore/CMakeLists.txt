# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(cmstore_icmstore INTERFACE)
target_include_directories(cmstore_icmstore INTERFACE ${IFACE_DIR})
target_link_libraries(cmstore_icmstore INTERFACE base ctistore::ictistore)
add_library(cmstore::icmstore ALIAS cmstore_icmstore)

# Implementation
add_library(cmstore_cmstore STATIC
    ${SRC_DIR}/cmstore.cpp
)
target_include_directories(cmstore_cmstore
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(cmstore_cmstore
    PUBLIC
    base
    cmstore::icmstore
)
add_library(cmstore::cmstore ALIAS cmstore_cmstore)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(cmstore_mocks INTERFACE)
target_include_directories(cmstore_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(cmstore_mocks INTERFACE GTest::gmock cmstore::icmstore)
add_library(cmstore::mocks ALIAS cmstore_mocks)


add_executable(cmstore_utest
    ${UNIT_SRC_DIR}/cmstore_test.cpp
)
target_link_libraries(cmstore_utest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    cmstore::cmstore
)
target_include_directories(cmstore_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(cmstore_utest)

add_executable(cmstore_ctest
    ${COMPONENT_SRC_DIR}/cmstore_test.cpp
)

target_link_libraries(cmstore_ctest PRIVATE cmstore::cmstore GTest::gtest_main)
gtest_discover_tests(cmstore_ctest)

endif(ENGINE_BUILD_TEST)

