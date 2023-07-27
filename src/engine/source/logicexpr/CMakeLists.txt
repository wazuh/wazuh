# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(logicexpr INTERFACE)
target_include_directories(logicexpr INTERFACE ${IFACE_DIR})
target_link_libraries(logicexpr INTERFACE parsec base)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_executable(logicexprTokenizer_test
    ${TEST_SRC_DIR}/tokenizer_test.cpp
)
target_link_libraries(logicexprTokenizer_test logicexpr gtest_main)
gtest_discover_tests(logicexprTokenizer_test)

add_executable(logicexprToken_test
    ${TEST_SRC_DIR}/token_test.cpp
)
target_link_libraries(logicexprToken_test logicexpr gtest_main)
gtest_discover_tests(logicexprToken_test)

add_executable(logicexprParser_test
    ${TEST_SRC_DIR}/parser_test.cpp
)
target_link_libraries(logicexprParser_test logicexpr gtest_main)
gtest_discover_tests(logicexprParser_test)


endif(ENGINE_BUILD_TEST)
