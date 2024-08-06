add_library(cmds STATIC
    src/graph.cpp
    src/start.cpp
    src/tester.cpp
    src/kvdb.cpp
    src/catalog.cpp
    src/config.cpp
    src/router.cpp
    src/metrics.cpp
    src/policy.cpp
    src/geo.cpp
)

target_link_libraries(cmds
    base
    yml
    defs
    builder
    #bk::taskf
    bk::rx
    server
    router::router
    store
    api
    libuv::uv_a
    kvdb
    conf::cliconf
    conf::iconf
    eMessages
    metrics
    geo
    schemf
    wdb
    sockiface
    rbac
    geo::igeo
)

target_include_directories(cmds
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(cmds_utest
    ${UNIT_SRC_DIR}/stackExecutor_test.cpp
    ${UNIT_SRC_DIR}/cli11_test.cpp
)
target_include_directories(cmds_utest
    PRIVATE
    ${TEST_SRC_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/src
)
target_link_libraries(cmds_utest
    PRIVATE
    GTest::gtest_main
    cmds
    base
    CLI11::CLI11
)
gtest_discover_tests(cmds_utest)

endif(ENGINE_BUILD_TEST)
