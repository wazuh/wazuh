# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

# # Interface
add_library(policy_ipolicy INTERFACE)
target_include_directories(policy_ipolicy INTERFACE ${IFACE_DIR})
target_link_libraries(policy_ipolicy INTERFACE fmt base json store::istore)
add_library(policy::ipolicy ALIAS policy_ipolicy)

# # policy
add_library(policy STATIC
    ${SRC_DIR}/policy.cpp
)
target_include_directories(policy
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(policy policy::ipolicy builder::ivalidator)

# Tests
if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
    set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

    # # Mocks
    add_library(policy_mocks INTERFACE)
    target_include_directories(policy_mocks INTERFACE ${TEST_MOCK_DIR})
    target_link_libraries(policy_mocks INTERFACE gmock policy::ipolicy)
    add_library(policy::mocks ALIAS policy_mocks)

    # # policy component test
    add_executable(policy_ctest
        ${COMPONENT_SRC_DIR}/policy_test.cpp
    )
    target_link_libraries(policy_ctest gtest_main policy)
    gtest_discover_tests(policy_ctest)

    add_executable(policy_utest
        ${UNIT_SRC_DIR}/policy_test.cpp
    )
    target_link_libraries(policy_utest gtest_main policy::mocks policy)
    gtest_discover_tests(policy_utest)
endif(ENGINE_BUILD_TEST)
