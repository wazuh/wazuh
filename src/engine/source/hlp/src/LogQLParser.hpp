#ifndef _LOGQL_PARSER_H
#define _LOGQL_PARSER_H

#include <string>
#include <vector>

enum class ExpresionType
{
    Capture,
    OptionalCapture,
    OrCapture,
    Literal,
};

struct Expresion
{
    std::string_view text;
    ExpresionType type;
    char endToken;
};

using ExpresionList = std::vector<Expresion>;
ExpresionList parseLogQlExpr(std::string const &expr);

#endif //_LOGQL_PARSER_H
