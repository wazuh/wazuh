add_library(router STATIC
    src/runtimePolicy.cpp
    src/policyManager.cpp
    src/router.cpp
    src/route.cpp
)

target_link_libraries(router
    PUBLIC
    # For api::Route, needs knos runtimeEnvironment becouse know runtimeEnvironment
    builders
    bk::taskf
    queue
    PRIVATE
    base
    json
    store::istore
)

target_include_directories(router
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)
