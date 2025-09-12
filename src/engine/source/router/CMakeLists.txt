# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# Interface
add_library(router_irouter INTERFACE)
target_include_directories(router_irouter INTERFACE ${IFACE_DIR})
target_link_libraries(router_irouter INTERFACE base)
add_library(router::irouter ALIAS router_irouter)

# Implementation
add_library(router_router STATIC
    ${SRC_DIR}/table.cpp
    ${SRC_DIR}/environment.cpp
    ${SRC_DIR}/router.cpp
    ${SRC_DIR}/tester.cpp
    ${SRC_DIR}/worker.cpp
    ${SRC_DIR}/entryConverter.cpp

    ${SRC_DIR}/orchestrator.cpp
)

target_include_directories(router_router
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(router_router
    PUBLIC
    router::irouter
    builder::ibuilder
    bk::ibk
    queue::iqueue

    PRIVATE
    base
    store::istore
    builder::ibuilder
)
add_library(router::router ALIAS router_router)

# Tests
if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
    set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

    # Mocks
    add_library(router_mocks INTERFACE)
    target_include_directories(router_mocks INTERFACE ${TEST_MOCK_DIR})
    target_link_libraries(router_mocks INTERFACE GTest::gmock router::irouter)
    add_library(router::mocks ALIAS router_mocks)

    # Router component test
    add_executable(router_ctest
        ${COMPONENT_SRC_DIR}/router_test.cpp
        ${COMPONENT_SRC_DIR}/tester_test.cpp
    )
    target_include_directories(router_ctest PRIVATE ${SRC_DIR})
    target_link_libraries(router_ctest
        GTest::gmock_main
        base
        router::router
        builder::mocks
        store::mocks
        bk::mocks
        queue::mocks
    )

    # Router unit test
    add_executable(router_utest
        ${UNIT_SRC_DIR}/entryConverter_test.cpp
        ${UNIT_SRC_DIR}/environment_test.cpp
        ${UNIT_SRC_DIR}/environmentBuilder_test.cpp
        ${UNIT_SRC_DIR}/router_test.cpp
        ${UNIT_SRC_DIR}/tester_test.cpp
        ${UNIT_SRC_DIR}/table_test.cpp
        ${UNIT_SRC_DIR}/orchestrator_test.cpp
        ${UNIT_SRC_DIR}/epsCounter_test.cpp
    )
    target_include_directories(router_utest PRIVATE ${SRC_DIR})
    target_link_libraries(router_utest
        GTest::gmock_main
        base
        router::router
        builder::mocks
        store::mocks
        bk::mocks
        bk::rx
        queue::mocks
    )
    gtest_discover_tests(router_utest router_ctest)
endif(ENGINE_BUILD_TEST)
