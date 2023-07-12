add_library(cmds STATIC
    src/graph.cpp
    src/start.cpp
    src/test.cpp
    src/kvdb.cpp
    src/catalog.cpp
    src/config.cpp
    src/router.cpp
    src/metrics.cpp
    src/integration.cpp
)

target_link_libraries(cmds
    base
    json
    yml
    defs
    builders
    rxbk
    server
    router
    store::fileDriver
    api
    uv_a
    conf::cliconf
    conf::iconf
    eMessages
    metrics
    schemf
    wdb
    sockiface
    rbac
)

target_include_directories(cmds
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${uvw_SOURCE_DIR}/src/ # TODO For the each client shared the client
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CLI11_SOURCE_DIR}/include
)
