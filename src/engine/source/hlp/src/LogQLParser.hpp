#ifndef _LOGQL_PARSER_H
#define _LOGQL_PARSER_H

#include <string>
#include <vector>

enum class ExpressionType
{
    Capture,
    OptionalCapture,
    OrCapture,
    Literal,
};

struct Expression
{
    std::string_view text;
    ExpressionType type;
    char endToken;
};

using ExpressionList = std::vector<Expression>;
ExpressionList parseLogQlExpr(std::string const &expr);

#endif //_LOGQL_PARSER_H
