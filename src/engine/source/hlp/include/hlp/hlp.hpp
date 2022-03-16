#ifndef _HLP_H
#define _HLP_H
#include <functional>
#include <string>
#include <unordered_map>

using ParseResult = std::unordered_map<std::string, std::string>;
using ParserFn = std::function<bool(std::string_view const &, ParseResult &)>;

/**
 * @brief Gets a parser operator from a logQL expression.
 *        This method parse a complete logQL expression to create and bind all
 * the different specific parsers capables to resolve an event matching with
 * that expression.
 *
 * @return ParserFn A Parser Function capable to parse an event.
 */
ParserFn getParserOp(std::string_view const &logQl);

#endif // _HLP_H
