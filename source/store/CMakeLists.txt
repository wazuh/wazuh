# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

set(DRIVER_DIR ${CMAKE_CURRENT_LIST_DIR}/drivers)

## Interface
add_library(store_istore INTERFACE)
target_include_directories(store_istore INTERFACE ${IFACE_DIR})
target_link_libraries(store_istore INTERFACE base)
add_library(store::istore ALIAS store_istore)

## File driver
add_library(store_fileDriver STATIC
    ${DRIVER_DIR}/fileDriver/src/fileDriver.cpp
)
target_include_directories(store_fileDriver
    PUBLIC
    ${DRIVER_DIR}/fileDriver/include
)
target_link_libraries(store_fileDriver store::istore)
add_library(store::fileDriver ALIAS store_fileDriver)

## Store
add_library(store STATIC
    ${SRC_DIR}/store.cpp
)
target_include_directories(store
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(store store::istore)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
add_library(store_mocks INTERFACE)
target_include_directories(store_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(store_mocks INTERFACE GTest::gmock store::istore)
add_library(store::mocks ALIAS store_mocks)

## File driver tests
add_executable(store_fileDriver_unit_test
    ${UNIT_SRC_DIR}/fileDriver_test.cpp
)
target_link_libraries(store_fileDriver_unit_test GTest::gtest_main store::fileDriver)
gtest_discover_tests(store_fileDriver_unit_test)

# TODO FIX THIS CMAKE (Separe unit tests from component tests)
## Store component test
add_executable(store_ctest
    ${COMPONENT_SRC_DIR}/store_test.cpp
)
target_link_libraries(store_ctest GTest::gtest_main store::fileDriver store)
gtest_discover_tests(store_ctest)

add_executable(store_utest
    ${UNIT_SRC_DIR}/store_test.cpp
)
target_link_libraries(store_utest GTest::gtest_main store::mocks store)
gtest_discover_tests(store_utest)

endif(ENGINE_BUILD_TEST)
