#ifndef _HLP_H
#define _HLP_H

#include <string>

using ParseResult = std::unordered_map<std::string, std::string>;
using ParserFn = std::function<ParseResult(std::string)>;

enum class CombType {
    Null,
    Optional,
};

enum class ParserType {
    Keyword,
    Literal,
    IP,
    Ts,
    Json,
    Invalid,
};

struct Parser {
    ParserType parserType;
    CombType combType;
    std::string name; // TODO: SSO saves us the alloc here
                      // but check if we can avoid the copy
    char endToken;
};

using ParserList = std::vector<Parser>;

void executeParserList(std::string const &event, ParserList const &parsers, ParseResult &result);
ParserFn getParserOp(std::string const &logQl);

#endif // _HLP_H
