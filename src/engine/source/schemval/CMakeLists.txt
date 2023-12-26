# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

## Interface
add_library(schemval_ivalidator INTERFACE)
target_include_directories(schemval_ivalidator INTERFACE ${IFACE_DIR})
target_link_libraries(schemval_ivalidator INTERFACE hlp schemf::ischema json)
add_library(schemval::ivalidator ALIAS schemval_ivalidator)

## Lib
add_library(schemval
    ${SRC_DIR}/validator.cpp
)
target_include_directories(schemval
    PUBLIC
        ${INC_DIR}

    PRIVATE
        ${INC_DIR}/schemval
        ${SRC_DIR}
)
target_link_libraries(schemval
    PUBLIC
        schemval::ivalidator
)



# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
add_library(schemval_mocks INTERFACE)
target_include_directories(schemval_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(schemval_mocks INTERFACE schemval::ivalidator gmock)
add_library(schemval::mocks ALIAS schemval_mocks)

## Component test
add_executable(schemval_ctest
    ${COMPONENT_SRC_DIR}/validator_test.cpp
)
target_link_libraries(schemval_ctest
    PRIVATE
        schemval
        schemf::mocks
        gtest_main
)
gtest_discover_tests(schemval_ctest)

## Unit tests TODO: fix
# add_executable(schemval_utest
#     ${UNIT_SRC_DIR}/validator_test.cpp
# )
# target_link_libraries(schemval_utest
#     PRIVATE
#         schemval
#         gtest_main
#         schemval::mocks
#         schemf::mocks
# )
# gtest_discover_tests(schemval_utest)

endif(ENGINE_BUILD_TEST)
