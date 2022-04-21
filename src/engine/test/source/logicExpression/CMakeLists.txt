add_executable(logicExpression_test
  ${TEST_SOURCE_DIR}/logicExpression/logicExpression_test.cpp
  ${ENGINE_SOURCE_DIR}/logicExpression/src/logicExpressionParser.cpp
)
target_include_directories(logicExpression_test
  PUBLIC ${ENGINE_SOURCE_DIR}/logicExpression/include/logicExpression
  PUBLIC ${ENGINE_SOURCE_DIR}/logicExpression/src
)

target_link_libraries(logicExpression_test gtest_main base)

gtest_discover_tests(logicExpression_test)
