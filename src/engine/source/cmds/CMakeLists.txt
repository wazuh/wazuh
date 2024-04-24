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
    json
    yml
    defs
    builder
    #bk::taskf
    bk::rx
    server
    router::router
    store
    api
    uv_a
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
    date::date
    geo::igeo
)

target_include_directories(cmds
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${uvw_SOURCE_DIR}/src/ # TODO For the each client shared the client
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CLI11_SOURCE_DIR}/include
)
