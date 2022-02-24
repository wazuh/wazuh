#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "LogQLParser.hpp"
#include "hlpDetails.hpp"

static const std::unordered_map<std::string_view, ParserType> kECSParserMapper {
    { "source.ip", ParserType::IP },
    { "server.ip", ParserType::IP },
    { "source.nat.ip", ParserType::IP },
    { "timestamp", ParserType::Ts },
    { "threat.indicator.first_seen", ParserType::Ts},
    { "file.accessed", ParserType::Ts},
    { "file.created", ParserType::Ts},
    { "url", ParserType::URL},
    { "http.request.method", ParserType::Any },
    { "client", ParserType::Domain}
};

static const std::unordered_map<std::string_view, ParserType> kTempTypeMapper {
    { "JSON", ParserType::JSON },
    { "MAP", ParserType::Map},
    { "timestamp", ParserType::Ts},
    { "domain", ParserType::Domain},
    { "FilePath", ParserType::FilePath},
};

struct Tokenizer {
    const char *stream;
};

enum class TokenType {
    _EndOfAscii = 256,
    OpenAngle,
    CloseAngle,
    QuestionMark,
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

static Token getToken(Tokenizer &tk) {
    const char *c = tk.stream++;

    switch (c[0]) {
        case '<': return { "<", 1, TokenType::OpenAngle };
        case '>': return { ">", 1, TokenType::CloseAngle };
        case '?': return { "?", 1, TokenType::QuestionMark };
        case '\0': return { 0, 0, TokenType::EndOfExpr };
        default: {
            bool escaped = false;
            while (tk.stream[0] && (escaped || (tk.stream[0] != '<' && tk.stream[0] != '>'))) {
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

static Token peekToken(Tokenizer const &tk) {
    Tokenizer tmp { tk.stream };
    return getToken(tmp);
}

static char peekChar(Tokenizer const &tk) {
    return tk.stream[0];
}

static std::vector<std::string> splitSlashSeparatedField(std::string_view str){
    std::vector<std::string> ret;
    while (true) {
        auto pos = str.find('/');
        if (pos == str.npos) {
            break;
        }
        ret.emplace_back(str.substr(0, pos));
        str = str.substr(pos + 1);
    }

    if (!str.empty()) {
        ret.emplace_back(str);
    }

    return ret;
}

static Parser parseCaptureString(Token token) {
    // TODO assert token type
    // TODO report errors
    std::vector<std::string> captureParams;

    // We could be parsing:
    //      '<_>'
    //      '<_name>'
    //      '<_name/type>'
    //      '<_name/type/type2>'
    captureParams = splitSlashSeparatedField({ token.text, token.len });
    Parser parser;
    parser.combType = CombType::Null;
    parser.endToken = 0;
    parser.name = captureParams[0];
    captureParams.erase(captureParams.begin());
    parser.parserType = ParserType::Any;
    if (token.text[0] == '_') {
        if (token.len != 1) {
            // We have a temp capture with the format <_temp/type/typeN>
            // we need to take the first parameter after the name and set the type from it
            if(!captureParams.empty()){
                auto it = kTempTypeMapper.find(captureParams[0]);
                if(it != kTempTypeMapper.end()){
                    parser.parserType = it->second;
                }
                // erase the type from the list so we are
                // consistent with the non temp case
                captureParams.erase(captureParams.begin());
            }
        }
    }
    else{
        auto it = kECSParserMapper.find(parser.name);
        if (it != kECSParserMapper.end()) {
            parser.parserType = it->second;
        }
    }
    parser.captureOpts = std::move(captureParams);

    return parser;
}

static bool parseCapture(Tokenizer &tk, ParserList &parsers) {
    //<name> || <?name> || <name1>?<name2>
    Token token = getToken(tk);
    bool optional = false;
    if (token.type == TokenType::QuestionMark) {
        optional = true;
        token = getToken(tk);
    }

    if (token.type == TokenType::Literal) {
        parsers.emplace_back(parseCaptureString(token));

        if (!requireToken(tk, TokenType::CloseAngle)) {
            // TODO report parsing error
            return false;
        }

        // TODO check if there's a better way to do this
        if (optional) {
            parsers.back().combType = CombType::Optional;
        }

        if (peekToken(tk).type == TokenType::QuestionMark) {
            // We are parsing <name1>?<name2>
            // Discard the peeked '?'
            getToken(tk);

            if (!requireToken(tk, TokenType::OpenAngle)) {
                // TODO report error
                return false;
            }
            // Fix up the combType of the previous capture as this is now an OR
            auto &prevCapture = parsers.back();
            prevCapture.combType = CombType::Or;

            parsers.emplace_back(parseCaptureString(getToken(tk)));
            auto &currentCapture = parsers.back();
            currentCapture.combType = CombType::OrEnd;

            if (!requireToken(tk, TokenType::CloseAngle)) {
                // TODO report error
                return false;
            }

            char endToken = peekChar(tk);
            currentCapture.endToken = endToken;
            prevCapture.endToken = endToken;
        }
        else {
            // TODO Check if there's a better way to do this
            parsers.back().endToken = peekChar(tk);
        }
    }
    else {
        // TODO error
        return false;
    }

    return true;
}

ParserList parseLogQlExpr(std::string const &expr) {
    std::vector<Parser> parsers;
    Tokenizer tokenizer { expr.c_str() };

    bool done = false;
    while (!done) {
        Token token = getToken(tokenizer);
        switch (token.type) {
            case TokenType::OpenAngle: {
                const char *prev = tokenizer.stream - 1;

                if (!parseCapture(tokenizer, parsers)) {
                    // TODO report error
                    //  Reset the parser list to signify an error occurred
                    parsers.clear();
                    done = true;
                }

                if (peekToken(tokenizer).type == TokenType::OpenAngle) {
                    // TODO report error. Can't have two captures back to back
                    const char *end = tokenizer.stream;
                    while (*end++ != '>') {};
                    fprintf(stderr,
                            "Invalid capture expression detected [%.*s]. Can't have back to back "
                            "captures.\n",
                            (int)(end - prev),
                            prev);
                    // Reset the parser list to signify an error occurred
                    parsers.clear();
                    done = true;
                }
                break;
            }
            case TokenType::Literal: {
                parsers.push_back({ {},
                                    { token.text, token.text + token.len },
                                    ParserType::Literal,
                                    CombType::Null,
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

    return parsers;
}
