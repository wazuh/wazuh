add_library(router STATIC
    src/runtimeEnvironment.cpp
#    src/environmentManager.cpp
    src/router.cpp
)

target_link_libraries(router
    PRIVATE
    builders
    base
    json
    rxbk
)

target_include_directories(router
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CameronQueue_SOURCE_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/src
)
