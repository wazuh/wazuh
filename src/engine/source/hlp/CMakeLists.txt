# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project Settings
project(wazuh-engine)

set(ENGINE_HLP_SOURCE_DIR ${ENGINE_SOURCE_DIR}/hlp)

####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
    NAME RapidJSON
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG master
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
)

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main PRIVATE
    ${ENGINE_HLP_SOURCE_DIR}/hlp.cpp
    ${ENGINE_HLP_SOURCE_DIR}/LogQLParser.cpp
    ${ENGINE_HLP_SOURCE_DIR}/SpecificParsers.cpp
)

target_include_directories(main PUBLIC
    ${RapidJSON_SOURCE_DIR}/include/
    ${ENGINE_HLP_SOURCE_DIR}
)
