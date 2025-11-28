# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR   ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR   ${CMAKE_CURRENT_LIST_DIR}/include)


add_library(cmcrud_icmcrud INTERFACE)
target_include_directories(cmcrud_icmcrud INTERFACE ${IFACE_DIR})
target_link_libraries(cmcrud_icmcrud INTERFACE base cmstore::icmstore)
add_library(cmcrud::icmcrud ALIAS cmcrud_icmcrud)

# Implementation
add_library(cmcrud_cmcrud STATIC
    ${SRC_DIR}/cmcrudservice.cpp
)

target_include_directories(cmcrud_cmcrud
    PUBLIC
        ${INC_DIR}
    PRIVATE
        ${SRC_DIR}
)

target_link_libraries(cmcrud_cmcrud
    PUBLIC
        cmcrud::icmcrud
        builder::ibuilder
    PRIVATE
        yml
)

add_library(cmcrud::cmcrud ALIAS cmcrud_cmcrud)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR      ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR      ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR     ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(cmcrud_mocks INTERFACE)
target_include_directories(cmcrud_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(cmcrud_mocks INTERFACE GTest::gmock cmcrud::icmcrud)
add_library(cmcrud::mocks ALIAS cmcrud_mocks)

# Unit tests
add_executable(cmcrud_utest
    ${UNIT_SRC_DIR}/cmcrudservice_test.cpp
)
target_link_libraries(cmcrud_utest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        cmcrud::cmcrud
        cmcrud::mocks
        cmstore::mocks
        builder::mocks
)
target_include_directories(cmcrud_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(cmcrud_utest)

# Component tests
add_executable(cmcrud_ctest
    ${COMPONENT_SRC_DIR}/cmcrud_test.cpp
)
target_link_libraries(cmcrud_ctest
    PRIVATE
        GTest::gtest_main
        GTest::gmock
        cmcrud::cmcrud
        cmcrud::mocks
        cmstore::mocks
        builder::mocks
)
gtest_discover_tests(cmcrud_ctest)

endif(ENGINE_BUILD_TEST)
