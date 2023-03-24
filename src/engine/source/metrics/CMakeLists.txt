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
${ENGINE_METRICS_SOURCE_DIR}/metricsInstruments.cpp
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
