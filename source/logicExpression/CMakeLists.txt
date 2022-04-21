####################################################################################################
# Dependencies
####################################################################################################

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(logicExpression STATIC
    src/logicExpressionParser.hpp
    src/logicExpressionParser.cpp
)

target_link_libraries(logicExpression
    PUBLIC base)

target_include_directories(logicExpression
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
)
