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
    ${SRC_DIR}/builders/stage/indexerOutput.cpp

    # Map
    ${SRC_DIR}/builders/opmap/map.cpp
    # TODO: Move to separate files
    ${SRC_DIR}/builders/opmap/opBuilderHelperMap.cpp
    ${SRC_DIR}/builders/opmap/kvdb.cpp
    ${SRC_DIR}/builders/opmap/mmdb.cpp
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
    ${SRC_DIR}/builders/optransform/sca.cpp
    ${SRC_DIR}/builders/optransform/windows.cpp
)
target_include_directories(builder PUBLIC ${BUILDER_PUB_INCS} PRIVATE ${BUILDER_PRI_INCS})
target_link_libraries(builder
    PUBLIC
    builder::ibuilder
    store::istore
    defs::idefinitions
    schemf::ischema
    base
    kvdb::ikvdb
    geo::igeo
    sockiface::isock
    wdb::iwdb
    indexerconnector::iindexerconnector
    logpar

    PRIVATE
    re2::re2
    logicexpr
    date::date
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
target_link_libraries(builder_mocks INTERFACE GTest::gmock builder::ibuilder)
add_library(builder::mocks ALIAS builder_mocks)

## Component test
add_executable(builder_ctest
    ${COMPONENT_SRC_DIR}/builder_test.cpp
    ${COMPONENT_SRC_DIR}/validator_test.cpp
)
target_link_libraries(builder_ctest PRIVATE builder GTest::gtest_main schemf::mocks store::mocks defs::mocks sockiface::mocks base::test)
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
    ${UNIT_SRC_DIR}/builders/opfilter/regex_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/ip_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/arrayContains_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/types_test.cpp
    ${UNIT_SRC_DIR}/builders/opfilter/match_test.cpp

    # Map Builders
    ${UNIT_SRC_DIR}/builders/opmap/map_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/strTransform_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/intCalc_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/regex_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/ip_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/time_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/hash_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/kvdb_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/mmdb_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/activeResponse_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/upgradeConfirmation_test.cpp
    ${UNIT_SRC_DIR}/builders/opmap/wdb_test.cpp

    # Transform Builders
    ${UNIT_SRC_DIR}/builders/optransform/strTransform_test.cpp
    ${UNIT_SRC_DIR}/builders/optransform/jsonTransform_test.cpp
    ${UNIT_SRC_DIR}/builders/optransform/array_test.cpp
    ${UNIT_SRC_DIR}/builders/optransform/objectGet_test.cpp
    ${UNIT_SRC_DIR}/builders/optransform/sca_test.cpp
    ${UNIT_SRC_DIR}/builders/optransform/scaInternal_test.cpp
    ${UNIT_SRC_DIR}/builders/optransform/windows_test.cpp
    ${UNIT_SRC_DIR}/builders/optransform/hlp_test.cpp


    # Stage Builders
    ${UNIT_SRC_DIR}/builders/stage/check_test.cpp
    ${UNIT_SRC_DIR}/builders/stage/map_test.cpp
    ${UNIT_SRC_DIR}/builders/stage/normalize_test.cpp
    ${UNIT_SRC_DIR}/builders/stage/parse_test.cpp
    ${UNIT_SRC_DIR}/builders/stage/outputs_test.cpp
    ${UNIT_SRC_DIR}/builders/stage/fileOutput_test.cpp
    ${UNIT_SRC_DIR}/builders/stage/indexerOutput_test.cpp

)
target_include_directories(builder_utest PRIVATE ${BUILDER_PRI_INCS} ${TEST_SRC_DIR} ${UNIT_SRC_DIR})
target_link_libraries(builder_utest
    PUBLIC
    GTest::gtest_main

    PRIVATE
    builder
    builder::mocks
    schemf::mocks
    store::mocks
    defs::mocks
    kvdb::mocks
    sockiface::mocks
    wdb::mocks
    geo::mocks
    base::test
    indexerconnector::mocks
)
gtest_discover_tests(builder_utest)

endif(ENGINE_BUILD_TEST)
