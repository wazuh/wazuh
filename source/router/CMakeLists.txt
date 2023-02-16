add_library(router STATIC
    src/runtimeEnvironment.cpp
    src/environmentManager.cpp
    src/router.cpp
    src/route.cpp
)

target_link_libraries(router
    PUBLIC
    # For api::Route, needs knos runtimeEnvironment becouse know runtimeEnvironment
    builders
    rxbk
    PRIVATE
    base
    json
    store::istore
)

target_include_directories(router
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CameronQueue_SOURCE_DIR}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)
