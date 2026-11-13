# SPDX-License-Identifier: AGPL-3.0-or-later
# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(wIndexerConnector_iwIndexerConnector INTERFACE)
target_include_directories(wIndexerConnector_iwIndexerConnector INTERFACE ${IFACE_DIR})
target_link_libraries(wIndexerConnector_iwIndexerConnector INTERFACE base)
add_library(wIndexerConnector::iwIndexerConnector ALIAS wIndexerConnector_iwIndexerConnector)

# Implementation
add_library(wIndexerConnector_wIndexerConnector STATIC
    ${SRC_DIR}/windexerconnector.cpp
    ${SRC_DIR}/engineConfigSource.cpp
    ${SRC_DIR}/engineIndexerRuntime.cpp
    ${SRC_DIR}/indexerMetrics.cpp
)
target_include_directories(wIndexerConnector_wIndexerConnector
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SHARED_MODULES}/keystore/include
)
target_link_libraries(wIndexerConnector_wIndexerConnector
    PUBLIC
    base
    wIndexerConnector::iwIndexerConnector
    indexer_client
    # registerIndexerMetrics() takes the fastmetrics IManager.
    fastmetrics::ifastmetrics
    PRIVATE
    # Keystore::get: keystore_core is keystore without its Log::GLOBAL_LOG_FUNCTION, which the engine defines
    # (base) and assigns, so the keystore logs reach the engine's sink.
    keystore_core
)
add_library(wIndexerConnector::wIndexerConnector ALIAS wIndexerConnector_wIndexerConnector)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(wIndexerConnector_mocks INTERFACE)
target_include_directories(wIndexerConnector_mocks INTERFACE ${TEST_MOCK_DIR} ${INC_DIR})
target_link_libraries(wIndexerConnector_mocks INTERFACE GTest::gmock wIndexerConnector::iwIndexerConnector)
add_library(wIndexerConnector::mocks ALIAS wIndexerConnector_mocks)

add_executable(wIndexerConnector_utest
    ${UNIT_SRC_DIR}/wic_test.cpp
    ${UNIT_SRC_DIR}/engineConfigSource_test.cpp
    ${UNIT_SRC_DIR}/engineIndexerRuntime_test.cpp
    ${UNIT_SRC_DIR}/indexerMetrics_test.cpp
)
target_link_libraries(wIndexerConnector_utest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    wIndexerConnector::wIndexerConnector
    wIndexerConnector::mocks
    fastmetrics::fastmetrics
)
# The client library's mocks and its in-process fake indexer (header-only, written on cpp-httplib, whose include
# directory the engine already adds).
target_include_directories(wIndexerConnector_utest PRIVATE ${SRC_DIR} ${SHARED_MODULES}/keystore/include
    ${SHARED_MODULES}/indexer_client/tests/mocks ${SHARED_MODULES}/indexer_client/tests/fake)
gtest_discover_tests(wIndexerConnector_utest PROPERTIES RESOURCE_LOCK "rocks_db_lock")

endif(ENGINE_BUILD_TEST)
