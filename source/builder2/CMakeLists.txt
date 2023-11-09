# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

## Interface
add_library(builder2_ibuilder INTERFACE)
target_include_directories(builder2_ibuilder INTERFACE ${IFACE_DIR})
target_link_libraries(builder2_ibuilder INTERFACE base) # Base for expression
add_library(builder2::ibuilder ALIAS builder2_ibuilder)

## Lib
add_library(builder2 STATIC
    ${SRC_DIR}/builder.cpp
    ${SRC_DIR}/policy/policy.cpp
)
target_include_directories(builder2
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
    ${INC_DIR}/builder
)
target_link_libraries(builder2
    PUBLIC
    builder2::ibuilder
    store::istore
    schemf::ischema
    base
    json
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
add_library(builder2_mocks INTERFACE)
target_include_directories(builder2_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(builder2_mocks INTERFACE gmock builder2::ibuilder)
add_library(builder2::mocks ALIAS builder2_mocks)

## Component test
add_executable(builder2_ctest
    ${COMPONENT_SRC_DIR}/builder_test.cpp
)
target_link_libraries(builder2_ctest PRIVATE builder2::ibuilder builder2::mocks gtest_main)
gtest_discover_tests(builder2_ctest)

## Unit tests
add_executable(builder2_utest
    ${UNIT_SRC_DIR}/registry/registry_test.cpp
    ${UNIT_SRC_DIR}/policy/policy_test.cpp
)
target_include_directories(builder2_utest PRIVATE ${SRC_DIR} PUBLIC ${INC_DIR})
target_link_libraries(builder2_utest PRIVATE builder2 builder2::mocks gtest_main schemf::mocks)
gtest_discover_tests(builder2_utest)

endif(ENGINE_BUILD_TEST)
