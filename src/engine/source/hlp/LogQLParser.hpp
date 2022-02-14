#ifndef _LOGQL_PARSER_H
#define _LOGQL_PARSER_H

#include <string>
#include "hlp.hpp"

using ParserList = std::vector<Parser>;
ParserList parseLogQlExpr(std::string const &expr);

#endif //_LOGQL_PARSER_H
