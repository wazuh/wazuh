#ifndef _H_HLP_DETAILS
#define _H_HLP_DETAILS

#include <string>
#include <unordered_map>
#include <vector>

#include <hlp/hlp.hpp>

/**
 * @brief Parsers enum type
 */
enum class ParserType
{
    Any,
    ToEnd, //TODO: can this be avoided merging it with Any parser?
    Literal,
    IP,
    Ts,
    URL,
    JSON,
    Map,
    Domain,
    FilePath,
    UserAgent,
    Number,
    QuotedString,
    Boolean,
    Invalid,
};

enum class ExpressionType;

/**
 * @brief Parser struct
 */
struct Parser
{
    std::vector<std::string> options;
    std::string name;
    ParserType type;
    ExpressionType expType;
    char endToken;
};

using parserFuncPtr =
    bool (*)(const char **it,
             Parser const &parser,
             ParseResult &result);

using parserConfigFuncPtr = bool (*)(Parser &parser,
                                     std::vector<std::string_view> const &args);

/**
 * @brief List with the available parser functions
 */
extern const parserFuncPtr kAvailableParsers[];

/**
 * @brief List with the configuration functions of the available parsers
 */
extern const parserConfigFuncPtr kParsersConfig[];
#endif //_H_HLP_DETAILS
