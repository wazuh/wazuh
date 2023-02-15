# FIXME: Base should be refactored to be an OBJECT library so other modules can simply include what they need.
####################################################################################################
# Profiler
####################################################################################################
if(ENGINE_PROFILE_BUILD)
    if( CMAKE_BUILD_TYPE STREQUAL "Release")
        message(WARNING "Prefer 'RelWithDebInfo' build config when trying to profile")
    elseif(NOT CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        message(FATAL_ERROR "Trying to profile a non-release build")
    endif()

    CPMAddPackage(
        NAME tracy
        GITHUB_REPOSITORY wolfpld/tracy
        GIT_TAG "v0.8"
        OPTIONS
        )

    add_library(profile
        OBJECT
        profile/profile.hpp
        )

    if(ENGINE_PROFILE_MEMORY)
        target_sources(profile
            PRIVATE
            profile/profile.cpp
            )
    endif()

    target_include_directories(profile
        PUBLIC
        ${tracy_SOURCE_DIR}/
        )

    target_link_libraries(profile PUBLIC TracyClient dl pthread)

    target_compile_definitions(profile PUBLIC WAZUH_PROFILING_ENABLED TRACY_ENABLE)
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
    GIT_TAG 8261c1ddf43f10de00fd8c9a67811d1486b2c784 # Latest master commit from 21/03/2022
    OPTIONS
    "RAPIDJSON_BUILD_DOC OFF"
    "RAPIDJSON_BUILD_EXAMPLES OFF"
    "RAPIDJSON_BUILD_TESTS OFF"
    DOWNLOAD_ONLY YES
    )

add_library(base STATIC
    logging/logging.hpp
    utils/socketInterface/unixInterface.cpp
    utils/socketInterface/unixInterface.hpp
    utils/socketInterface/unixSecureStream.hpp
    utils/socketInterface/unixSecureStream.cpp
    utils/socketInterface/unixDatagram.cpp
    utils/socketInterface/unixDatagram.hpp
    utils/wazuhProtocol/wazuhResponse.hpp
    utils/wazuhProtocol/wazuhRequest.hpp
    utils/wazuhProtocol/wazuhRequest.cpp
    utils/baseMacros.hpp
    utils/baseMacros.cpp
    utils/ipUtils.cpp
    utils/ipUtils.hpp
    utils/stringUtils.cpp
    utils/stringUtils.hpp
    result.hpp
    baseTypes.hpp
    expression.cpp
    error.hpp
    parseEvent.cpp
    parseEvent.hpp
    name.hpp
    )

if(PROFILE_BUILD)
    target_link_libraries(base
        PUBLIC
        profile
        )
endif()

target_link_libraries(base
    PUBLIC
    dl
    fmt
    json
    )

target_include_directories(base
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${fmtlog_SOURCE_DIR}
    ${rapidjson_SOURCE_DIR}/include
    ${ENGINE_SOURCE_DIR}/json
    )
