# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)
SET (BUILDER_BUILDERS_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/builders)

####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)
list(APPEND EXTERNAL_DEPS "rxcpp")

CPMAddPackage(
  NAME RE2
  GITHUB_REPOSITORY google/re2
  GIT_TAG 2022-02-01
  VERSION release 2022-02-01
)
list(APPEND EXTERNAL_DEPS "re2")

CPMAddPackage(
  NAME rapidjson
  GITHUB_REPOSITORY Tencent/rapidjson
  GIT_TAG master
  VERSION 1.1.0
  OPTIONS
      "RAPIDJSON_BUILD_DOC OFF"
      "RAPIDJSON_BUILD_EXAMPLES OFF"
      "RAPIDJSON_BUILD_TESTS OFF"
)
FetchContent_GetProperties(
  rapidjson
  SOURCE_DIR rapidjson_headers
)

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main PRIVATE
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${ENGINE_SOURCE_DIR}/shared/stringUtils.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderRule.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderDecoder.cpp
)

target_include_directories(main PUBLIC
    ${BUILDER_ENGINE_SOURCE_DIR}
    ${BUILDER_ENGINE_SOURCE_DIR}/outputs
    ${BUILDER_ENGINE_SOURCE_DIR}/builders
    ${ENGINE_SOURCE_DIR}/shared
    ${rapidjson_headers}/include
)
