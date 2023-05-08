set(ENGINE_API_SOURCE_DIR ${ENGINE_SOURCE_DIR}/api/src)
set(ENGINE_API_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/api/include)

# ###################################################################################################
# Dependencies
# ###################################################################################################
# yaml-cpp::yaml-cpp vs yaml-cpp #FIXME 70 stars on github
CPMAddPackage(
    NAME yaml-cpp
    GITHUB_REPOSITORY jbeder/yaml-cpp
    GIT_TAG yaml-cpp-0.7.0
    VERSION 0.7.0
    OPTIONS
    "YAML_BUILD_SHARED_LIBS OFF"
    "YAML_CPP_BUILD_TESTS OFF"
    EXCLUDE_FROM_ALL YES
)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(api STATIC
    ${ENGINE_API_SOURCE_DIR}/api.cpp
    ${ENGINE_API_SOURCE_DIR}/catalog/catalog.cpp
    ${ENGINE_API_SOURCE_DIR}/catalog/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/graph/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/integration/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/integration/integration.cpp
    ${ENGINE_API_SOURCE_DIR}/kvdb/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/metrics/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/registry.cpp
    ${ENGINE_API_SOURCE_DIR}/router/handlers.cpp
)

target_include_directories(api
    PUBLIC
    ${ENGINE_API_INCLUDE_DIR}
    PRIVATE
    ${ENGINE_API_SOURCE_DIR}
    ${ENGINE_API_SOURCE_DIR}/catalog
    ${ENGINE_API_SOURCE_DIR}/graph
    ${ENGINE_API_SOURCE_DIR}/integration
    ${ENGINE_API_SOURCE_DIR}/kvdb
    ${ENGINE_API_SOURCE_DIR}/metrics
    ${ENGINE_API_SOURCE_DIR}/router
)

target_link_libraries(api
    base
    builder::ivalidator
    eMessages
    fmt
    json
    kvdb
    metrics
    router
    store::fileDriver
    store::istore
    yaml-cpp
)
