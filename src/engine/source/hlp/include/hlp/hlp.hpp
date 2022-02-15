#ifndef _HLP_H
#define _HLP_H
#include <functional>
#include <string>
#include <unordered_map>

using ParseResult = std::unordered_map<std::string, std::string>;
using ParserFn = std::function<ParseResult(std::string)>;

ParserFn getParserOp(std::string const &logQl);

#endif // _HLP_H
