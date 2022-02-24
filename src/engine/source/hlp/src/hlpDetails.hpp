#include <string>
#include <vector>

enum class CombType {
    Null,
    Optional,
    Or,
    OrEnd,
    Invalid,
};

enum class ParserType {
    Any,
    Literal,
    IP,
    Ts,
    URL,
    JSON,
    Map,
    Domain,
    FilePath,
    Invalid,
};

struct Parser {
    std::vector<std::string> captureOpts; // TODO The options are split on a list for now
                                          // This is probably not the best way but works so far
    std::string name;
    ParserType parserType;
    CombType combType;
    char endToken;
};
