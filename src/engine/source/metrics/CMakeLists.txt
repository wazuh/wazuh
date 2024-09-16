# Refactor WIP - Metrics
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

## Interface
add_library(metrics_imetrics INTERFACE)
target_include_directories(metrics_imetrics INTERFACE ${IFACE_DIR})
target_link_libraries(metrics_imetrics INTERFACE base)
add_library(metrics::imetrics ALIAS metrics_imetrics)

## Metrics
add_library(metricsWIP STATIC
    ${SRC_DIR}/exporter/indexerMetricsExporter.cpp
)
target_include_directories(metricsWIP
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(metricsWIP
  PUBLIC
  metrics::imetrics
  base

  PRIVATE
  opentelemetry-cpp::api
  opentelemetry-cpp::metrics
  opentelemetry-cpp::sdk
  opentelemetry-cpp::resources
  indexerconnector::iindexerconnector
)

## Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(metrics_utest
  ${UNIT_SRC_DIR}/exporter/indexerMetricsExporter_test.cpp
)
target_include_directories(metrics_utest
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(metrics_utest
  GTest::gtest_main
  metricsWIP
  indexerconnector::mocks
  opentelemetry-cpp::api
  opentelemetry-cpp::metrics
  opentelemetry-cpp::sdk
  opentelemetry-cpp::resources
  base::test
)
gtest_discover_tests(metrics_utest)

endif(ENGINE_BUILD_TEST)

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
