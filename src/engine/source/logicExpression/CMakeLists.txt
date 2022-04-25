####################################################################################################
# Dependencies
####################################################################################################

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(logicExpression STATIC
    ${ENGINE_SOURCE_DIR}/logicExpression/include/logicExpression/logicExpression.hpp
    src/logicExpressionParser.hpp
    src/logicExpressionParser.cpp
    src/logicExpressionEvaluator.hpp
)

target_link_libraries(logicExpression
    PUBLIC base)

target_include_directories(logicExpression
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
)
