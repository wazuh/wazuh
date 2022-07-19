set(ENGINE_JSON_SOURCE_DIR ${ENGINE_SOURCE_DIR}/json/src)
set(ENGINE_JSON_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/json/include)

####################################################################################################
# Dependencies
####################################################################################################

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(json STATIC
    ${ENGINE_JSON_SOURCE_DIR}/json.cpp
)

target_link_libraries(json PUBLIC base )

target_include_directories(json PUBLIC
    ${ENGINE_JSON_INCLUDE_DIR}
)
