set(ENGINE_METRICS_SOURCE_DIR ${ENGINE_SOURCE_DIR}/metrics/src)
set(ENGINE_METRICS_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/metrics/include)

####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
    NAME opentelemetry
    GITHUB_REPOSITORY open-telemetry/opentelemetry-cpp
    GIT_TAG v1.8.2
    VERSION 1.8.2
    EXCLUDE_FROM_ALL YES
    OPTIONS
        "BUILD_TESTING OFF"
        "WITH_ZIPKIN ON" # TODO: Add build option and link zipkin to it. Define OT modules policy.
)

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

target_link_libraries(metrics PUBLIC
opentelemetry_api
opentelemetry_sdk
opentelemetry_exporter_ostream_metrics
opentelemetry_resources
PRIVATE base)

target_include_directories(metrics PUBLIC
${ENGINE_METRICS_INCLUDE_DIR}
)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/unit)

add_executable(metrics_test
  ${TEST_SRC_DIR}/interface_test.cpp
  ${TEST_SRC_DIR}/mocks/metricsAuxiliarFunctions.hpp
)

# TODO: Replace test_mocks with the metrics executable when you have the test folder available.
target_link_libraries(metrics_test gtest_main base test_mocks)
gtest_discover_tests(metrics_test)
endif(ENGINE_BUILD_TEST)
