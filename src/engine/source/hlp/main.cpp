#include <algorithm>
#include <functional>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

enum class CombType {
    Null,
    Optional,
};

enum class ParserType {
    Keyword,
    Literal,
    IP,
    Ts,
    Invalid,
};

struct Parser {
    ParserType parserType;
    CombType combType;
    std::string name; // TODO: SSO saves us the alloc here
                      // but check if we can avoid the copy
    char endToken;
};

static const std::unordered_map<std::string_view, ParserType> ECSParserMapper {
    { "source.ip", ParserType::Keyword },
    { "timestamp", ParserType::Keyword },
    { "http.reqest.method", ParserType::Keyword },
};

using ParserList = std::vector<Parser>;

struct Tokenizer {
    const char *stream;
    std::vector<Parser> parsers;
};

enum class TokenType {
    _EndOfAscii = 256,
    OpenAngle,
    CloseAngle,
    QuestionMark,
    Slash,
    Literal,
    EndOfExpr,
    Unknown,
    Error,
};

struct Token {
    const char *text;
    size_t len;
    TokenType type;
};

static bool literalEquals(Token const &token, const char *ident) {
    const char *text = token.text;
    for (int i = 0; i < token.len; ++i) {
        if (*text++ != *ident++)
            return false;
    }

    return *ident == '\0';
}

static Token getToken(Tokenizer &tk) {
    const char *c = tk.stream++;

    switch (c[0]) {
        case '<': return { "<", 1, TokenType::OpenAngle };
        case '>': return { ">", 1, TokenType::CloseAngle };
        case '?': return { "?", 1, TokenType::QuestionMark };
        case '/': return { "/", 1, TokenType::Slash };
        case '\0': return { 0, 0, TokenType::EndOfExpr };
        default: {
            bool escaped = false;
            while (tk.stream[0] && !(!escaped && (tk.stream[0] == '<' || tk.stream[0] == '>'))) {
                tk.stream++;
                escaped = tk.stream[0] == '\\';
            }
            return { c, static_cast<size_t>(tk.stream - c), TokenType::Literal };
        }
    }

    // TODO unreachable
    return { 0, 0, TokenType::Unknown };
}

bool requireToken(Tokenizer &tk, TokenType req) {
    return getToken(tk).type == req;
}

Token peekToken(Tokenizer const &tk) {
    Tokenizer tmp { tk.stream };
    return getToken(tmp);
}

char peekChar(Tokenizer const &tk) {
    return tk.stream[0];
}

static Parser parseCaptureName(Token token) {
    // TODO assert token type
    if (token.text[0] == '_') {
        if (token.len == 1) {
            fprintf(stderr, "Got anonymous capture\n");
        }
        else {
            // TODO parse type
        }
    }

    ParserType type = ParserType::Keyword;
    auto it = ECSParserMapper.find({ token.text, token.len });
    if (it != ECSParserMapper.end()) {
        type = it->second;
    }

    return { type, CombType::Null, { token.text, token.text + token.len }, 0 };
}

static void parseCapture(Tokenizer &tk) {
    //<name> || <?name> || <name1>?<name2>
    Token token = getToken(tk);
    bool optional = false;
    if (token.type == TokenType::QuestionMark) {
        optional = true;
        token = getToken(tk);
    }

    if (token.type == TokenType::Literal) {
        tk.parsers.emplace_back(parseCaptureName(token));

        if (!requireToken(tk, TokenType::CloseAngle)) {
            // TODO report parsing error
        }

        // TODO Check if there's a better way to do this
        tk.parsers.back().endToken = peekChar(tk);
    }
    else {
        // TODO error
    }
}

ParserList parseLogQlExpr(std::string const &expr) {
    bool done = false;
    Tokenizer tokenizer { expr.c_str() };
    while (!done) {
        Token token = getToken(tokenizer);
        switch (token.type) {
            case TokenType::OpenAngle: {
                parseCapture(tokenizer);
                break;
            }
            case TokenType::Literal: {
                tokenizer.parsers.push_back({ ParserType::Literal,
                                              CombType::Null,
                                              { token.text, token.text + token.len },
                                              0 });
                break;
            }
            case TokenType::EndOfExpr: {
                done = true;
                break;
            }
            default: {
                // TODO
                break;
            }
        }
    }

    return tokenizer.parsers;
}

using ParseResult = std::unordered_map<std::string, std::string>;

bool parseFilePath(const char **it, char endToken) {
    const char *start = *it;
    while (**it != endToken) { (*it)++; }
    return true;
}

bool parseURI(char **it, char endToken) {
    return true;
}

bool parseTimeStamp(char **it, char endToken) {
    return true;
}

bool parseJson(const char **it, char endToken, ParseResult &result) {
    const char *start = *it;
    while (**it != endToken) { (*it)++; }

    std::string_view sw { start, (size_t)((*it) - start) };
    // json::parse(sw);
    return true;
};

std::string parseAny(const char **it, char endToken, ParseResult &result) {
    const char *start = *it;
    while (**it != endToken) { (*it)++; }
    return { start, *it };
}

bool matchLiteral(const char **it, std::string /*the copy is intentional*/ literal) {
    // TODO Check if there's a better way to avoid the string copy + the remove algorithm
    literal.erase(std::remove(literal.begin(), literal.end(), '\\'), literal.end());
    int i = 0;
    for (; (**it) && (i < literal.size()); ++i) {
        if (**it != literal[i]) {
            return false;
        }
        (*it)++;
    }

    return literal[i] == '\0';
}

void executeParserList(std::string const &event, ParserList const &parsers, ParseResult &result) {
    const char *eventIt = event.c_str();

    // TODO This implementation is super simple for the POC
    // but we will want to re-do it or revise it to implement
    // better parser combinations
    bool error = false;
    printf("%30s | %4s | %4s | %4s\n", "Capture", "type", "comb", "etok");
    printf("-------------------------------|------|------|------\n");
    for (auto const &parser : parsers) {
        printf("%-30s | %4i | %4i | '%1c'\n",
               parser.name.c_str(),
               parser.parserType,
               parser.combType,
               parser.endToken);

        switch (parser.parserType) {
            case ParserType::Keyword: {
                auto ret = parseAny(&eventIt, parser.endToken, result);
                if (!ret.empty()) {
                    result[parser.name] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            case ParserType::Literal: {
                if (!matchLiteral(&eventIt, parser.name)) {
                    fprintf(stderr, "Failed matching literal string\n");
                    error = true;
                }
                break;
            }
            default: {
                fprintf(stderr,
                        "Missing implementation for parser type: [%i]\n",
                        parser.parserType);
                break;
            }
        }

        if (error) {
            break;
        }
    }
}

auto getParserOp(std::string const &logQl) {
    auto parserList = parseLogQlExpr(logQl);

    auto parseFn = [expr = logQl, parserList = std::move(parserList)](std::string const &event) {
        printf("event:\n\t%s\n\t%s\n\n", event.c_str(), expr.c_str());
        ParseResult result;
        executeParserList(event, parserList, result);
        return result;
    };

    return parseFn;
}

static const char *str = "C:\\Users\\usuario\\Documents\\prueba.html ";
static const char *str2 = "/usr/lib/sendmail.cf ";

static const char *logQl =
    "<source.address> - - [<timestamp/APACHE>] \"<http.request.method> <url> HTTP/<http.version>\" "
    "<http.response.status_code> <http.response.body.bytes> \"-\" \"<user_agent.original>\"";
static const char *event =
    "monitoring-server - - [29/May/2017:19:02:48 +0000] \"GET /status HTTP/1.1\" 200 612 \"-\" "
    "\"Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2\"";

static const char *logQl2 = "<source.ip> - - [<timestamp/APACHE>] \"-\" "
                            "<http.response.status_code> <http.response.body.bytes> \"-\" \"-\"";
static const char *event2 = "127.0.0.1 - - [02/Feb/2019:05:38:45 +0100] \"-\" 408 152 \"-\" \"-\"";

int main(int argc, char **argv) {
    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);
    putchar('\n');
    printf("%30s | %s\n", "Key", "Val");
    printf("-------------------------------|------------\n");
    for (auto const &r : result) { printf("%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    putchar('\n');

    auto parseOp2 = getParserOp(logQl2);
    auto result2 = parseOp2(event2);
    putchar('\n');
    printf("%30s | %s\n", "Key", "Val");
    printf("-------------------------------|------------\n");
    for (auto const &r : result2) { printf("%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    return 0;
}
