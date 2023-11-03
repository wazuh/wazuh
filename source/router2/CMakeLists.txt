# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# Interface
add_library(router2_irouter INTERFACE)
target_include_directories(router2_irouter INTERFACE ${IFACE_DIR})
target_link_libraries(router2_irouter INTERFACE base)
add_library(router2::irouter ALIAS router2_irouter)

# Implementation
add_library(router2_router STATIC
   ${SRC_DIR}/environment.cpp
   ${SRC_DIR}/table.cpp
)

target_include_directories(router2_router
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(router2_router
    PUBLIC
    router2::irouter
    bk::ibk

    PRIVATE
    base

)
add_library(router2::router ALIAS router2_router)

# Tests
if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
    set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

    # # Mocks
    # add_library(router2_mocks INTERFACE)
    # target_include_directories(router2_mocks INTERFACE ${TEST_MOCK_DIR})
    # target_link_libraries(router2_mocks INTERFACE gmock router2::irouter)
    # add_library(router2::mocks ALIAS router2_mocks)

    # # Router component test
    # add_executable(router_ctest
    #     ${COMPONENT_SRC_DIR}/router_test.cpp
    # )
    # target_link_libraries(router_ctest gtest_main router2::irouter router2::router)
    # gtest_discover_tests(router2_ctest)

    # Router unit test
    add_executable(router_utest
        ${UNIT_SRC_DIR}/environment_test.cpp
    )
    target_include_directories(router_utest PRIVATE ${SRC_DIR})
    target_link_libraries(router_utest gtest_main router2::irouter router2::router)
    gtest_discover_tests(router_utest)

endif(ENGINE_BUILD_TEST)
