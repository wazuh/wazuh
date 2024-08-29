# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(logicexpr INTERFACE)
target_include_directories(logicexpr INTERFACE ${IFACE_DIR})
target_link_libraries(logicexpr INTERFACE parsec base)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_executable(logicexpr_test
    ${TEST_SRC_DIR}/tokenizer_test.cpp
    ${TEST_SRC_DIR}/token_test.cpp
    ${TEST_SRC_DIR}/parser_test.cpp
    ${TEST_SRC_DIR}/evaluator_test.cpp
    ${TEST_SRC_DIR}/logicexpr_test.cpp
)
target_link_libraries(logicexpr_test logicexpr GTest::gtest_main)
gtest_discover_tests(logicexpr_test)



endif(ENGINE_BUILD_TEST)
