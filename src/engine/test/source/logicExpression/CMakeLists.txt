add_executable(logicExpression_test
  ${TEST_SOURCE_DIR}/logicExpression/logicExpressionParser_test.cpp
  ${ENGINE_SOURCE_DIR}/logicExpression/src/logicExpressionParser.cpp
  ${TEST_SOURCE_DIR}/logicExpression/logicExpressionEvaluator_test.cpp
  ${TEST_SOURCE_DIR}/logicExpression/logicExpression_test.cpp
)
target_include_directories(logicExpression_test
  PUBLIC ${ENGINE_SOURCE_DIR}/logicExpression/include
  PUBLIC ${ENGINE_SOURCE_DIR}/logicExpression/src
)

target_link_libraries(logicExpression_test gtest_main base)

gtest_discover_tests(logicExpression_test)
