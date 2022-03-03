#ifndef _HLP_H
#define _HLP_H
#include <functional>
#include <string>
#include <unordered_map>
#include "rapidjson/document.h"

using ParseResultold = std::unordered_map<std::string, std::string>;
using ParserFnold = std::function<ParseResultold(std::string)>;

using ParserResult = rapidjson::Document;                   // Return from each parser method
using ParserFn = std::function<bool(const char**, ParserResult&)>; // The Parser methods type (receives a c_string and returns a result)
using ParserFnList = std::vector<ParserFn>;                 // The list of all the parsers already configured
using ParserOp = std::function<bool(std::string, ParserResult&)>; //The executor, receives an event string and returns a result

ParserFnold getParserOpold(std::string const &logQl);
ParserOp getParserOp(std::string const &logQl);

#endif // _HLP_H
