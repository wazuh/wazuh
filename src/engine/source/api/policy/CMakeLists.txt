set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(api_policy_ipolicy INTERFACE)
target_include_directories(api_policy_ipolicy INTERFACE ${IFACE_DIR})
target_link_libraries(api_policy_ipolicy INTERFACE base eMessages store::istore)
add_library(api::policy::ipolicy ALIAS api_policy_ipolicy)

add_library(api_policy STATIC
  ${SRC_DIR}/policy.cpp
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_policy
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_policy
    PUBLIC
    base
    api::policy::ipolicy
    api::adapter
    store::istore
    builder::ibuilder
)
add_library(api::policy ALIAS api_policy)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_library(api_policy_mocks INTERFACE)
    target_include_directories(api_policy_mocks INTERFACE ${TEST_MOCK_DIR})
    target_link_libraries(api_policy_mocks INTERFACE api::policy::ipolicy GTest::gmock)
    add_library(api::policy::mocks ALIAS api_policy_mocks)

    add_executable(api_policy_utest
        ${UNIT_SRC_DIR}/policy_test.cpp
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_policy_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_policy_utest
        PRIVATE
        api::policy
        api::policy::mocks
        GTest::gtest_main
        builder::mocks
        store::mocks
        api::adapter::test
    )
    gtest_discover_tests(api_policy_utest)
endif()
