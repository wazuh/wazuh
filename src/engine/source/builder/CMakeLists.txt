# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Minimum 3.14 required by googletest discover tests

set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)
SET (BUILDER_BUILDERS_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/builders)

####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
  NAME RE2
  GITHUB_REPOSITORY google/re2
  GIT_TAG 2022-02-01
  VERSION release 2022-02-01
  EXCLUDE_FROM_ALL YES
)

####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main PRIVATE
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderRule.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderDecoder.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageParse.cpp
)

target_include_directories(main PUBLIC
    ${BUILDER_ENGINE_SOURCE_DIR}
    ${BUILDER_ENGINE_SOURCE_DIR}/outputs
    ${BUILDER_ENGINE_SOURCE_DIR}/builders
    ${rapidjson_headers}/include
)

#TODO do this better
target_link_libraries(main re2)
