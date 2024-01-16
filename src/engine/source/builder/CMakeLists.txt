# TODO: QoL keep an eye on exposing linked libraries to the user
# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

## Interface
add_library(builder_ibuilder INTERFACE)
target_include_directories(builder_ibuilder INTERFACE ${IFACE_DIR})
target_link_libraries(builder_ibuilder INTERFACE base) # Base for expression
add_library(builder::ibuilder ALIAS builder_ibuilder)

## Builders Obj Lib
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

## Lib
SET(BUILDER_PUB_INCS
    ${INC_DIR}
)
SET(BUILDER_PRI_INCS
    ${SRC_DIR}
    ${INC_DIR}/builder
)
add_library(builder STATIC
    ${SRC_DIR}/builder.cpp
    ${SRC_DIR}/policy/factory.cpp
    ${SRC_DIR}/policy/policy.cpp
    ${SRC_DIR}/policy/assetBuilder.cpp
    ${SRC_DIR}/builders/baseHelper.cpp

    # Stage
    ${SRC_DIR}/builders/stage/check.cpp
    ${SRC_DIR}/builders/stage/map.cpp
    ${SRC_DIR}/builders/stage/parse.cpp
    ${SRC_DIR}/builders/stage/normalize.cpp
    ${SRC_DIR}/builders/stage/outputs.cpp
    ${SRC_DIR}/builders/stage/fileOutput.cpp

    # Map
    ${SRC_DIR}/builders/opmap/map.cpp
    # TODO: Move to separate files
    ${SRC_DIR}/builders/opmap/opBuilderHelperMap.cpp
    ${SRC_DIR}/builders/opmap/kvdb.cpp
    ${SRC_DIR}/builders/opmap/activeResponse.cpp
    ${SRC_DIR}/builders/opmap/upgradeConfirmation.cpp
    ${SRC_DIR}/builders/opmap/wdb.cpp

    # Filter
    ${SRC_DIR}/builders/opfilter/filter.cpp
    ${SRC_DIR}/builders/opfilter/startsWith.cpp
    ${SRC_DIR}/builders/opfilter/exists.cpp
    # TODO: Move to separate files
    ${SRC_DIR}/builders/opfilter/opBuilderHelperFilter.cpp

    # Transform
    ${SRC_DIR}/builders/optransform/array.cpp
    ${SRC_DIR}/builders/optransform/hlp.cpp
    ${SRC_DIR}/builders/optransform/netinfoAddress.cpp
    ${SRC_DIR}/builders/optransform/sca.cpp
    ${SRC_DIR}/builders/optransform/windows.cpp
)
target_include_directories(builder PUBLIC ${BUILDER_PUB_INCS} PRIVATE ${BUILDER_PRI_INCS})
# TODO make variables so we can use them in the tests and make private the dependencies
target_link_libraries(builder
    PUBLIC
    builder::ibuilder
    store::istore
    base
    defs::idefinitions
    schemval::ivalidator
    re2
    logicexpr
    logpar
    date::date
    kvdb::mocks
    sockiface::mocks
    wdb::mocks
    schemf::mocks

    PRIVATE

    schemf::ischema

)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
add_library(builder_mocks INTERFACE)
target_include_directories(builder_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(builder_mocks INTERFACE gmock builder::ibuilder)
add_library(builder::mocks ALIAS builder_mocks)

## Component test
add_executable(builder_ctest
    ${COMPONENT_SRC_DIR}/builder_test.cpp
)
target_link_libraries(builder_ctest PRIVATE builder gtest_main)
gtest_discover_tests(builder_ctest)

## Unit tests
add_executable(builder_utest
    ${UNIT_SRC_DIR}/registry_test.cpp
    ${UNIT_SRC_DIR}/policy/factory_test.cpp
    ${UNIT_SRC_DIR}/policy/assetBuilder_test.cpp
    ${UNIT_SRC_DIR}/builders/helperParser_test.cpp
    ${UNIT_SRC_DIR}/builders/baseBuilders_test.cpp

    # Filter Builders
    ${UNIT_SRC_DIR}/builders/opfilter/filter_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/exists_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/startsWith_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/intCmp_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/strCmp_test.cpp

    # Map Builders
    ${UNIT_SRC_DIR}/builders/opmap/map_test.cpp
)
target_include_directories(builder_utest PUBLIC ${BUILDER_PUB_INCS} PRIVATE ${BUILDER_PRI_INCS} ${TEST_SRC_DIR} ${UNIT_SRC_DIR})
target_link_libraries(builder_utest
    PRIVATE
    builder
    builder::mocks
    gtest_main
    schemf::mocks
    store::mocks
    defs::mocks
    schemval::mocks
)
gtest_discover_tests(builder_utest)

endif(ENGINE_BUILD_TEST)
