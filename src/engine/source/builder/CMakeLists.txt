# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
# ###################################################################################################
# Dependencies
# ###################################################################################################

# If debug is enabled, Add the RE2_ON_VALGRIND definition for RE2
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(RE2_ON_VALGRIND)
endif()

CPMAddPackage(
  NAME RE2
  GITHUB_REPOSITORY google/re2
  GIT_TAG 2022-02-01
  VERSION release 2022-02-01
  EXCLUDE_FROM_ALL YES
)

# TODO: as in curl library this should be added statically inside the project
find_package(OpenSSL REQUIRED)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(builder_ivalidator INTERFACE)
target_include_directories(builder_ivalidator INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
target_link_libraries(builder_ivalidator INTERFACE base json)
add_library(builder::ivalidator ALIAS builder_ivalidator)

add_library(builders OBJECT
  asset.cpp
  builders/baseHelper.cpp
  builders/opBuilderFileOutput.cpp
  builders/opBuilderHelperActiveResponse.cpp
  builders/opBuilderHelperFilter.cpp
  builders/opBuilderHelperMap.cpp
  builders/opBuilderHelperNetInfoAddress.cpp
  builders/opBuilderKVDB.cpp
  builders/opBuilderLogParser.cpp
  builders/opBuilderSCAdecoder.cpp
  builders/opBuilderSpeficHLP.cpp
  builders/opBuilderWdb.cpp
  builders/operationBuilder.cpp
  builders/stageBuilderCheck.cpp
  builders/stageBuilderMap.cpp
  builders/stageBuilderNormalize.cpp
  builders/stageBuilderOutputs.cpp
  builders/stageBuilderParse.cpp
  definitions.cpp
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
target_link_libraries(builders
  builder::ivalidator
  store::istore
  base
  hlp2
  kvdb
  re2
  logicExpression
  wdb
  OpenSSL::Crypto
)
