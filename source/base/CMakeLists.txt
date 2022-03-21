####################################################################################################
# Profiler
####################################################################################################
if(PROFILE_BUILD)
    if( CMAKE_BUILD_TYPE STREQUAL "Release")
        message(WARNING "Prefer 'RelWithDebInfo' build config when trying to profile")
    elseif(NOT CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        message(FATAL_ERROR "Trying to profile a non-release build")
    endif()

    CPMAddPackage(
        NAME tracy
        GITHUB_REPOSITORY wolfpld/tracy
        GIT_TAG "v0.7.8"
        OPTIONS
        )

    add_library(profile STATIC ${tracy_SOURCE_DIR}/TracyClient.cpp )
    target_include_directories(profile PUBLIC ${tracy_SOURCE_DIR}/)
    target_link_libraries(profile PUBLIC dl pthread)

    target_compile_definitions(profile PUBLIC WAZUH_PROFILING_ENABLED TRACY_ENABLE)
    #target_compile_definitions(profile PUBLIC TRACY_NO_EXIT)
endif()

####################################################################################################
# logging
####################################################################################################
CPMAddPackage(
    NAME fmt
    GITHUB_REPOSITORY fmtlib/fmt
    GIT_TAG "8.1.1"
    )

CPMAddPackage(
    NAME fmtlog
    GITHUB_REPOSITORY MengRao/fmtlog
    GIT_TAG "v2.1.3"
    DOWNLOAD_ONLY YES
    )

####################################################################################################
# json
####################################################################################################
CPMAddPackage(
    NAME rapidjson
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG master
    VERSION 1.1.0
    OPTIONS
    "RAPIDJSON_BUILD_DOC OFF"
    "RAPIDJSON_BUILD_EXAMPLES OFF"
    "RAPIDJSON_BUILD_TESTS OFF"
    DOWNLOAD_ONLY YES
    )

add_library(base STATIC
    logging/logging.hpp
    utils/ipUtils.cpp
    utils/ipUtils.hpp
    utils/stringUtils.cpp
    utils/stringUtils.hpp
    )

if(PROFILE_BUILD)
    target_link_libraries(base
        PUBLIC
        profile
        )
endif()

target_link_libraries(base
    PUBLIC
    fmt
    )

target_include_directories(base
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    INTERFACE
    ${fmtlog_SOURCE_DIR}
    ${rapidjson_SOURCE_DIR}/include
    )
