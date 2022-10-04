add_library(cmds STATIC
    src/cmdGraph.cpp
    src/cmdRun.cpp
    src/cmdTest.cpp
    src/cmdKvdb.cpp
)

target_link_libraries(cmds PRIVATE
    base
    json
    builders
    catalog
    rxbk
    server
    store::fileDriver
)

target_include_directories(cmds PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(cmds PRIVATE
    ${CameronQueue_SOURCE_DIR}
)
