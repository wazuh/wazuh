# ###################################################################################################
# Dependencies
# ###################################################################################################
CPMAddPackage(
    NAME rapidjson
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG 8261c1ddf43f10de00fd8c9a67811d1486b2c784 # Latest master commit from 21/03/2022
    OPTIONS
    "RAPIDJSON_BUILD_DOC OFF"
    "RAPIDJSON_BUILD_EXAMPLES OFF"
    "RAPIDJSON_BUILD_TESTS OFF"
    DOWNLOAD_ONLY YES
)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(json STATIC
    ${CMAKE_CURRENT_LIST_DIR}/src/json.cpp
)

target_link_libraries(json fmt base)

target_include_directories(json PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${rapidjson_SOURCE_DIR}/include
)
