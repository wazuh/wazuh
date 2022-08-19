# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
# ###################################################################################################
# Dependencies
# ###################################################################################################
CPMAddPackage(
  NAME RE2
  GITHUB_REPOSITORY google/re2
  GIT_TAG 2022-02-01
  VERSION release 2022-02-01
  EXCLUDE_FROM_ALL YES
)

#TODO: as in curl library this should be added statically inside the project
find_package(OpenSSL REQUIRED)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(builders OBJECT
  builders/opBuilderFileOutput.cpp
  builders/stageBuilderCheck.cpp
  builders/stageBuilderNormalize.cpp
  builders/stageBuilderMap.cpp
  builders/operationBuilder.cpp
  builders/stageBuilderOutputs.cpp
  builders/stageBuilderParse.cpp
  builders/opBuilderLogqlParser.cpp
  builders/opBuilderKVDB.cpp
  builders/opBuilderHelperFilter.cpp
  builders/opBuilderHelperNetInfoAddress.cpp
  builders/opBuilderHelperMap.cpp
  builders/opBuilderHelperHashSHA1.cpp
  builders/baseHelper.cpp
  builders/opBuilderWdb.cpp
  builders/opBuilderARWrite.cpp
  definitions.cpp
  asset.cpp
  environment.cpp
  registry.cpp
)

target_include_directories(builders
  PRIVATE
  ${ENGINE_SOURCE_DIR}/wdb/src

  # TODO fix this?
  ${ENGINE_SOURCE_DIR}/builder/builders
  ${ENGINE_SOURCE_DIR}/json
  ${ENGINE_SOURCE_DIR}
  PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}
  ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

# TODO do this better. Also, who 'owns' the rxcpp dep
target_link_libraries(builders base hlp kvdb re2 logicExpression server wdb OpenSSL::Crypto)
