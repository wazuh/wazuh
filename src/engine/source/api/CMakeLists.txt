set(ENGINE_API_SOURCE_DIR ${ENGINE_SOURCE_DIR}/api/src)
set(ENGINE_API_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/api/include)

set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(api_iapi INTERFACE)
target_include_directories(api_iapi INTERFACE ${IFACE_DIR})
target_link_libraries(api_iapi INTERFACE base store::istore)
add_library(api::iapi ALIAS api_iapi)

add_library(api STATIC
  ${ENGINE_API_SOURCE_DIR}/api.cpp
  ${ENGINE_API_SOURCE_DIR}/catalog/catalog.cpp
  ${ENGINE_API_SOURCE_DIR}/catalog/handlers.cpp
  ${ENGINE_API_SOURCE_DIR}/graph/handlers.cpp
  ${ENGINE_API_SOURCE_DIR}/kvdb/handlers.cpp
  ${ENGINE_API_SOURCE_DIR}/metrics/handlers.cpp
  ${ENGINE_API_SOURCE_DIR}/policy/handlers.cpp
  ${ENGINE_API_SOURCE_DIR}/policy/policy.cpp
  ${ENGINE_API_SOURCE_DIR}/registry.cpp
  ${ENGINE_API_SOURCE_DIR}/router/handlers.cpp
  ${ENGINE_API_SOURCE_DIR}/tester/handlers.cpp
  ${ENGINE_API_SOURCE_DIR}/geo/handlers.cpp
)

target_include_directories(api
  PUBLIC
  ${ENGINE_API_INCLUDE_DIR}
  PRIVATE
  ${ENGINE_API_SOURCE_DIR}
  ${ENGINE_API_SOURCE_DIR}/catalog
  ${ENGINE_API_SOURCE_DIR}/graph
  ${ENGINE_API_SOURCE_DIR}/kvdb
  ${ENGINE_API_SOURCE_DIR}/metrics
  ${ENGINE_API_SOURCE_DIR}/policy
  ${ENGINE_API_SOURCE_DIR}/router
  ${ENGINE_API_SOURCE_DIR}/tester
  ${ENGINE_API_SOURCE_DIR}/geo
)

target_link_libraries(api
    base
    eMessages
    kvdb::ikvdb
    metrics
    router::irouter
    store::fileDriver
    store::istore
    yml
    schemf
    rbac::irbac
    api::iapi
    builder::ibuilder
    logpar
    geo::igeo
)

# Tests
if(ENGINE_BUILD_TEST)
  set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
  set(TEST_SRC_COMPONENT_DIR ${TEST_SRC_DIR}/component)
  set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
  set(TEST_SRC_UNIT_DIR ${TEST_SRC_DIR}/unit)

  # Mocks
  add_library(api_mocks INTERFACE)
  target_include_directories(api_mocks INTERFACE ${TEST_MOCK_DIR})
  target_link_libraries(api_mocks INTERFACE GTest::gmock api::iapi)
  add_library(api::mocks ALIAS api_mocks)

  add_executable(api_utest
    ${TEST_SRC_UNIT_DIR}/catalog/catalog_test.cpp
    ${TEST_SRC_UNIT_DIR}/catalog/handlers_test.cpp
    ${TEST_SRC_UNIT_DIR}/catalog/resource_test.cpp

    # TODO update the tests when builder has interface
    # ${TEST_SRC_UNIT_DIR}/graph/handlers_test.cpp
    ${TEST_SRC_UNIT_DIR}/kvdb/kvdb_api_test.cpp
    ${TEST_SRC_UNIT_DIR}/policy/handlers_test.cpp
    ${TEST_SRC_UNIT_DIR}/policy/policy_test.cpp
    ${TEST_SRC_UNIT_DIR}/router/handlers_test.cpp
    ${TEST_SRC_UNIT_DIR}/tester/handlers_test.cpp
    ${TEST_SRC_UNIT_DIR}/adapter_test.cpp
    ${TEST_SRC_UNIT_DIR}/api_test.cpp
    ${TEST_SRC_UNIT_DIR}/registry_test.cpp
    ${TEST_SRC_UNIT_DIR}/geo/handlers_test.cpp
  )

  target_link_libraries(api_utest
    GTest::gtest_main
    base
    base::test
    api
    schemf::mocks
    store::mocks
    rbac::mocks
    api::mocks
    kvdb::mocks
    router::mocks
    builder::mocks
    geo::mocks
)
gtest_discover_tests(api_utest)
endif(ENGINE_BUILD_TEST)

add_subdirectory(adapter)
add_subdirectory(catalog)
add_subdirectory(geo)
add_subdirectory(policy)
add_subdirectory(router)
add_subdirectory(tester)
add_subdirectory(kvdb)
add_subdirectory(event)
