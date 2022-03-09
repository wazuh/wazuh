#include <string>
#include <vector>
#include <unordered_map>

enum class ParserType
{
    Any,
    Literal,
    IP,
    Ts,
    URL,
    JSON,
    Map,
    Domain,
    FilePath,
    UserAgent,
    Invalid,
};

enum class ExpresionType;

struct Parser
{
    std::vector<std::string> options;
    std::string name;
    ParserType type;
    ExpresionType expType;
    char endToken;
};


using parserFuncPtr =
    bool (*)(const char **it,
             Parser const &parser,
             std::unordered_map<std::string, std::string> &result);

using parserConfigFuncPtr =
    bool (*)(Parser &parser, std::vector<std::string_view> const& args);

extern const parserFuncPtr kAvailableParsers[];
extern const parserConfigFuncPtr kParsersConfig[];
