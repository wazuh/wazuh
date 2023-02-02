####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
    NAME opentelemetry
    GITHUB_REPOSITORY open-telemetry/opentelemetry-cpp
    GIT_TAG v1.8.2
    VERSION 1.8.2
    EXCLUDE_FROM_ALL YES
    DOWNLOAD_ONLY
    OPTIONS
        "BUILD_TESTING OFF"
)

add_compile_definitions ( ONLY_C_LOCALE=1 )

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(metrics STATIC
    include/metrics.hpp
    src/metrics.cpp
)

target_link_libraries(metrics PRIVATE opentelemetry base)

target_include_directories(metrics
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
)
