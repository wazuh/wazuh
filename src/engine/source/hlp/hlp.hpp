#ifndef _HLP_H
#define _HLP_H

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

using ParseResult = std::unordered_map<std::string, std::string>;
using ParserFn = std::function<ParseResult(std::string)>;

enum class CombType {
    Null,
    Optional,
    Or,
    OrEnd,
    Invalid,
};

enum class ParserType {
    Any, Literal,
    IP,
    Ts,
    URL,
    JSON,
    Invalid,
};

struct Parser {
    std::vector<std::string> captureOpts; // TODO The options include the name on the first slot
                                          // This is probably not the best way but works so far
    ParserType parserType;
    CombType combType;
    char endToken;
};


ParserFn getParserOp(std::string const &logQl);

#endif // _HLP_H
