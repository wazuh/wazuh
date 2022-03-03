#ifndef _LOGQL_PARSER_H
#define _LOGQL_PARSER_H

#include <string>
#include <vector>
namespace LogQL
{

enum class Comb {
    Null,
    Optional,
    Or,
    OrEnd,
    Invalid,
};

enum class Type {
    Any,
    Literal,
    field,
};

struct Element {
    std::string name;
    std::string parser;
    std::string opts;
    Type type;
    Comb combType;
    char endToken;
    bool isTemp;
};

using ElementList = std::vector<Element>;

ElementList parseExpr(std::string const &expr);

}

enum ParserType {
    IP,
    Ts,
    URL,
    JSON,
    Map,
    Domain,
    FilePath,
    Invalid,
};




#endif //_LOGQL_PARSER_H
