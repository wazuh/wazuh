add_library(router STATIC
    src/runtimeEnvironment.cpp
    src/environmentManager.cpp
)

target_link_libraries(router PRIVATE
    base
    json
    builders
    rxbk
)

target_include_directories(router PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(router PRIVATE
    ${CameronQueue_SOURCE_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/src
)
