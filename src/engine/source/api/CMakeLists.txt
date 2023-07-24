set(ENGINE_API_SOURCE_DIR ${ENGINE_SOURCE_DIR}/api/src)
set(ENGINE_API_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/api/include)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(api STATIC
    ${ENGINE_API_SOURCE_DIR}/api.cpp
    ${ENGINE_API_SOURCE_DIR}/catalog/catalog.cpp
    ${ENGINE_API_SOURCE_DIR}/catalog/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/graph/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/integration/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/integration/integration.cpp
    ${ENGINE_API_SOURCE_DIR}/kvdb/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/metrics/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/registry.cpp
    ${ENGINE_API_SOURCE_DIR}/router/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/test/handlers.cpp
    ${ENGINE_API_SOURCE_DIR}/test/sessionManager.cpp
)

target_include_directories(api
    PUBLIC
    ${ENGINE_API_INCLUDE_DIR}
    PRIVATE
    ${ENGINE_API_SOURCE_DIR}
    ${ENGINE_API_SOURCE_DIR}/catalog
    ${ENGINE_API_SOURCE_DIR}/graph
    ${ENGINE_API_SOURCE_DIR}/integration
    ${ENGINE_API_SOURCE_DIR}/kvdb
    ${ENGINE_API_SOURCE_DIR}/metrics
    ${ENGINE_API_SOURCE_DIR}/router
    ${ENGINE_API_SOURCE_DIR}/test
)

target_link_libraries(api
    base
    builder::ivalidator
    eMessages
    fmt
    json
    kvdb
    metrics
    router
    store::fileDriver
    store::istore
    yml
    schemf
)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)

add_executable(api_test
  ${TEST_SRC_DIR}/apiAuxiliarFunctions.hpp
  ${TEST_SRC_DIR}/graph/handlers_test.cpp
  ${TEST_SRC_DIR}/graph/fakeAssets.hpp
  ${TEST_SRC_DIR}/test/session_test.cpp
  ${TEST_SRC_DIR}/test/handlers_test.cpp
  ${TEST_SRC_DIR}/test/fakeAssets.hpp
)

# TODO: Replace test_mocks with the metrics executable when you have the test folder available.
target_link_libraries(api_test gtest_main base api schemf::mocks test_mocks store_mocks)
gtest_discover_tests(api_test)
endif(ENGINE_BUILD_TEST)
