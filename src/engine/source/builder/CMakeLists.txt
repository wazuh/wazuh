# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
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
add_library(builders OBJECT
    builders/assetBuilderDecoder.cpp
    builders/assetBuilderFilter.cpp
    builders/assetBuilderOutput.cpp
    builders/assetBuilderRule.cpp
    builders/combinatorBuilderBroadcast.cpp
    builders/combinatorBuilderChain.cpp
    builders/opBuilderFileOutput.cpp
    builders/opBuilderHelperFilter.cpp
    builders/opBuilderHelperMap.cpp
    builders/opBuilderKVDB.cpp
    builders/stageBuilderCheck.cpp
    builders/stageBuilderNormalize.cpp
    builders/stageBuilderOutputs.cpp
    builders/stageParse.cpp
    definitions.cpp
)

target_include_directories(builders
    PRIVATE
    #TODO fix this?
    ${ENGINE_SOURCE_DIR}/json
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

#TODO do this better. Also, who 'owns' the rxcpp dep
target_link_libraries(builders base hlp kvdb re2)
