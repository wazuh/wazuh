#ifndef _LOG_PARSER_H
#define _LOG_PARSER_H

#include <string>
#include <vector>

/**
 * @brief Logpar expression elements enum type
 */
enum class ExpressionType
{
    Capture,
    OptionalCapture,
    OrCapture,
    Literal,
};

/**
 * @brief Logpar expression elements struct
 */
struct Expression
{
    std::string_view text;
    ExpressionType type;
    char endToken;
};

using ExpressionList = std::vector<Expression>;

/**
 * @brief Creates a list of expressions elements that represent the parser and
 * options extracted from a Logpar expression
 *
 * @param expr Logpar expression
 * @return std::vector with all the options in the string expression.
 * @note This function requires that the original string live for the duration
 *       that you need each piece as the vector refers to the original string
 */
ExpressionList parseLogExpr(const char* expr);

#endif //_LOG_PARSER_H
