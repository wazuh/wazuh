# Refactor WIP - Metrics
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(metrics_imetrics INTERFACE)
target_include_directories(metrics_imetrics INTERFACE ${IFACE_DIR})
target_link_libraries(metrics_imetrics INTERFACE base)
add_library(metrics::imetrics ALIAS metrics_imetrics)


set(ENGINE_METRICS_SOURCE_DIR ${ENGINE_SOURCE_DIR}/metrics/src)
set(ENGINE_METRICS_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/metrics/include)

add_compile_definitions ( ONLY_C_LOCALE=1 )

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(metrics STATIC
${ENGINE_METRICS_SOURCE_DIR}/metricsManager.cpp
${ENGINE_METRICS_SOURCE_DIR}/dataHub.cpp
${ENGINE_METRICS_SOURCE_DIR}/dataHubExporter.cpp
${ENGINE_METRICS_SOURCE_DIR}/metricsScope.cpp
)

target_link_libraries(metrics PRIVATE
  base
  opentelemetry-cpp::api
  opentelemetry-cpp::metrics
  opentelemetry-cpp::sdk
  opentelemetry-cpp::logs
)

target_include_directories(metrics PUBLIC
${ENGINE_METRICS_INCLUDE_DIR}
)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_UNIT_DIR ${CMAKE_CURRENT_LIST_DIR}/test/unit)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/unit/mocks)

add_executable(metrics_utest
  ${TEST_UNIT_DIR}/metricsManager_test.cpp
  ${TEST_UNIT_DIR}/dataHub_test.cpp
  ${TEST_UNIT_DIR}/dataHubExporter_test.cpp
  ${TEST_UNIT_DIR}/metricsScope_test.cpp
)

# Mocks
add_library(metrics_mocks INTERFACE)
target_include_directories(metrics_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(metrics_mocks INTERFACE GTest::gmock)
add_library(metrics::mocks ALIAS metrics_mocks)

target_include_directories(metrics_utest INTERFACE ${TEST_MOCK_DIR})

# TODO: Replace test_mocks with the metrics executable when you have the test folder available.
target_link_libraries(metrics_utest GTest::gtest_main GTest::gmock base metrics)
gtest_discover_tests(metrics_utest)
endif(ENGINE_BUILD_TEST)
