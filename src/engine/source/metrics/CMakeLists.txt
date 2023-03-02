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
#    DOWNLOAD_ONLY
    OPTIONS
        "BUILD_TESTING OFF"
        "WITH_ZIPKIN ON"
)

add_compile_definitions ( ONLY_C_LOCALE=1 )

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(metrics STATIC
${ENGINE_METRICS_SOURCE_DIR}/metrics.cpp
${ENGINE_METRICS_SOURCE_DIR}/exporterHandler.cpp
${ENGINE_METRICS_SOURCE_DIR}/processorHandler.cpp
${ENGINE_METRICS_SOURCE_DIR}/providerHandler.cpp
${ENGINE_METRICS_SOURCE_DIR}/readerHandler.cpp
)

target_link_libraries(metrics PUBLIC
opentelemetry_api
opentelemetry_sdk
opentelemetry_exporter_ostream_span
opentelemetry_exporter_in_memory
opentelemetry_exporter_zipkin_trace
opentelemetry_exporter_ostream_metrics
opentelemetry_resources
PRIVATE base)

target_include_directories(metrics PUBLIC
${ENGINE_METRICS_INCLUDE_DIR}
${FETCHCONTENT_BASE_DIR}/opentelemetry-src/exporters/zipkin/include
${FETCHCONTENT_BASE_DIR}/opentelemetry-src/exporters/ostream/include
)
