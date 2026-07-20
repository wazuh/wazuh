set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

## Interface library (pure interfaces for mocking)
add_library(fastmetrics_ifastmetrics INTERFACE)
target_include_directories(fastmetrics_ifastmetrics INTERFACE ${IFACE_DIR})
target_link_libraries(fastmetrics_ifastmetrics INTERFACE streamlogger::streamlogger)
add_library(fastmetrics::ifastmetrics ALIAS fastmetrics_ifastmetrics)

## Implementation library
add_library(fastmetrics_fastmetrics STATIC
    ${SRC_DIR}/manager.cpp
    ${SRC_DIR}/registry.cpp
)

target_include_directories(fastmetrics_fastmetrics
    PUBLIC
    ${INCLUDE_DIR}
    ${IFACE_DIR}

    PRIVATE
    ${SRC_DIR}
)

target_link_libraries(fastmetrics_fastmetrics
    PUBLIC
    fastmetrics::ifastmetrics
    base  # Required for SingletonLocator
    streamlogger::streamlogger
)

# Require C++17 for if constexpr and other features
target_compile_features(fastmetrics_fastmetrics PUBLIC cxx_std_17)

add_library(fastmetrics::fastmetrics ALIAS fastmetrics_fastmetrics)

## Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks library
add_library(fastmetrics_mocks INTERFACE)
target_include_directories(fastmetrics_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(fastmetrics_mocks INTERFACE
    fastmetrics::ifastmetrics
    GTest::gmock
)
add_library(fastmetrics::mocks ALIAS fastmetrics_mocks)

## Unit tests
add_executable(fastmetrics_utest
    ${UNIT_SRC_DIR}/registry_test.cpp
    ${UNIT_SRC_DIR}/counter_test.cpp
    ${UNIT_SRC_DIR}/gauge_test.cpp
    ${UNIT_SRC_DIR}/pullMetric_test.cpp
    ${UNIT_SRC_DIR}/slidingWindowRate_test.cpp
    ${UNIT_SRC_DIR}/main.cpp
)

target_include_directories(fastmetrics_utest
    PRIVATE
    ${SRC_DIR}
    ${UNIT_SRC_DIR}
)

target_link_libraries(fastmetrics_utest
    PRIVATE
    fastmetrics::fastmetrics
    fastmetrics::mocks
    GTest::gtest
    GTest::gmock
)

gtest_discover_tests(fastmetrics_utest)

## Component tests
add_executable(fastmetrics_ctest
    ${COMPONENT_SRC_DIR}/realistic_scenarios_test.cpp
)

target_include_directories(fastmetrics_ctest
    PRIVATE
    ${SRC_DIR}
)

target_link_libraries(fastmetrics_ctest
    PRIVATE
    fastmetrics::fastmetrics
    GTest::gtest_main
)

gtest_discover_tests(fastmetrics_ctest)

endif(ENGINE_BUILD_TEST)
