add_library(cmds STATIC
    src/cmdGraph.cpp
    src/cmdRun.cpp
    src/cmdTest.cpp
    src/cmdApiKvdb.cpp
    src/cmdApiCatalog.cpp
    src/cmdApiEnvironment.cpp
    src/apiclnt/connection.cpp
    src/stackExecutor.cpp
)

target_link_libraries(cmds PRIVATE
    base
    json
    builders
    rxbk
    server
    router
    store::fileDriver
    api
    uv_a
)

target_include_directories(cmds PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(cmds PRIVATE
    ${CameronQueue_SOURCE_DIR}
    ${uvw_SOURCE_DIR}/src/
    ${CMAKE_CURRENT_LIST_DIR}/src
)
