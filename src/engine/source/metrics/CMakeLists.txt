set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

## Interface
add_library(metrics_imetrics INTERFACE)
target_include_directories(metrics_imetrics INTERFACE ${IFACE_DIR})
target_link_libraries(metrics_imetrics INTERFACE base)
add_library(metrics::imetrics ALIAS metrics_imetrics)

## Metrics
add_library(metrics STATIC
    ${SRC_DIR}/exporter/indexerMetricsExporter.cpp
    ${SRC_DIR}/manager.cpp
)
target_include_directories(metrics
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
)
target_link_libraries(metrics
  PUBLIC
  metrics::imetrics
  base
  indexerconnector::iindexerconnector

  PRIVATE
  opentelemetry-cpp::api
  opentelemetry-cpp::metrics
  opentelemetry-cpp::sdk
  opentelemetry-cpp::resources
)

## Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
add_library(metrics_mocks INTERFACE)
target_include_directories(metrics_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(metrics_mocks INTERFACE metrics::imetrics)
add_library(metrics::mocks ALIAS metrics_mocks)

add_executable(metrics_utest
  ${UNIT_SRC_DIR}/exporter/indexerMetricsExporter_test.cpp
  ${UNIT_SRC_DIR}/manager_test.cpp
  ${UNIT_SRC_DIR}/mocks_test.cpp
  ${UNIT_SRC_DIR}/metrics/metrics_test.cpp
  ${UNIT_SRC_DIR}/main.cpp
)
target_include_directories(metrics_utest
  PRIVATE
  ${SRC_DIR}
  ${UNIT_SRC_DIR}
)
target_link_libraries(metrics_utest
  GTest::gtest
  metrics
  indexerconnector::mocks
  opentelemetry-cpp::api
  opentelemetry-cpp::metrics
  opentelemetry-cpp::sdk
  opentelemetry-cpp::resources
  base::test
  metrics::mocks
)
gtest_discover_tests(metrics_utest)

add_executable(metrics_ctest
  ${COMPONENT_SRC_DIR}/metrics_test.cpp
)
target_link_libraries(metrics_ctest
  GTest::gtest_main
  metrics
  indexerconnector::mocks
  base::test
)
gtest_discover_tests(metrics_ctest)

endif(ENGINE_BUILD_TEST)
