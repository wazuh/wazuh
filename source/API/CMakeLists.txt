set(ENGINE_API_SOURCE_DIR ${ENGINE_SOURCE_DIR}/API/src)
set(ENGINE_API_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/API/include)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(api STATIC
    ${ENGINE_API_SOURCE_DIR}/registry.cpp
    ${ENGINE_API_SOURCE_DIR}/wazuhRequest.cpp
    ${ENGINE_API_SOURCE_DIR}/wazuhResponse.cpp
)


target_link_libraries(api PRIVATE base)

target_include_directories(api
    PUBLIC
    ${ENGINE_API_INCLUDE_DIR}

    PRIVATE
    ${ENGINE_API_SOURCE_DIR}
    ${ENGINE_SOURCE_DIR}/json
)
