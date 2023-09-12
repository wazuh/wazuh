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
  OPTIONS
    "RE2_BUILD_TESTING OFF"
)

# TODO: as in curl library this should be added statically inside the project
find_package(OpenSSL REQUIRED)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(builder_ibuilder INTERFACE)
target_include_directories(builder_ibuilder INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
target_link_libraries(builder_ibuilder INTERFACE base json)
add_library(builder::ibuilder ALIAS builder_ibuilder)

add_library(builder_mocks INTERFACE)
target_include_directories(builder_mocks INTERFACE ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
target_link_libraries(builder_mocks INTERFACE builder::ibuilder)
add_library(builder::mocks ALIAS builder_mocks)

add_library(builders OBJECT
  asset.cpp
  builders/baseHelper.cpp
  builders/opBuilderFileOutput.cpp
  builders/opBuilderHelperActiveResponse.cpp
  builders/opBuilderHelperFilter.cpp
  builders/opBuilderHelperMap.cpp
  builders/opBuilderHelperNetInfoAddress.cpp
  builders/opBuilderHelperUpgradeConfirmation.cpp
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
  policy.cpp
  registry.cpp
)

target_include_directories(builders
  PRIVATE
  # TODO fix this?
  ${ENGINE_SOURCE_DIR}/builder/builders
  ${ENGINE_SOURCE_DIR}
  PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}
)

# TODO do this better. Also, who 'owns' the rxcpp dep
target_link_libraries(builders
  builder::ibuilder
  store::istore
  defs
  base
  hlp
  logpar
  kvdb
  re2
  logicexpr
  wdb::iwdb
  sockiface::isock
  json
  OpenSSL::Crypto
  schemf::ischema
  date::date
)
