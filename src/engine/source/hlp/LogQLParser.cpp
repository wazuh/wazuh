#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "LogQLParser.hpp"
#include "hlp.hpp"

static const std::unordered_map<std::string_view, ParserType> ECSParserMapper {
    { "source.ip", ParserType::IP },
    { "server.ip", ParserType::IP },
    { "source.nat.ip", ParserType::IP },
    { "timestamp", ParserType::Any },
    { "http.request.method", ParserType::Any },
    { "JSON", ParserType::JSON},
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

Token peekToken(Tokenizer const &tk) {
    Tokenizer tmp { tk.stream };
    return getToken(tmp);
}

char peekChar(Tokenizer const &tk) {
    return tk.stream[0];
}

std::vector<std::string> splitSlashSeparatedField(std::string_view str){
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
    ParserType type = ParserType::Any;
    std::vector<std::string> captureOpts;

    if (token.text[0] == '_') {
        // We could be parsing:
        //      '<_>'
        //      '<_name>'
        //      '<_name/type>'
        //      '<_name/type/type2>'
        if (token.len != 1) {
            captureOpts = splitSlashSeparatedField({ token.text, token.len });
        }
    }
    else {
        captureOpts = splitSlashSeparatedField({ token.text, token.len });

        auto it = ECSParserMapper.find({ token.text, token.len });
        if (it != ECSParserMapper.end()) {
            type = it->second;
        }
    }

    return { std::move(captureOpts), type, CombType::Null, 0 };
}

static void parseCapture(Tokenizer &tk, ParserList &parsers) {
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
            return;
        }

        if (peekToken(tk).type == TokenType::QuestionMark) {
            // We are parsing <name1>?<name2>
            // Discard the peeked '?'
            getToken(tk);

            if (!requireToken(tk, TokenType::OpenAngle)) {
                // TODO report error
                return;
            }
            // Fix up the combType of the previous capture as this is now an OR
            auto &prevCapture = parsers.back();
            prevCapture.combType = CombType::Or;

            parsers.emplace_back(parseCaptureString(token));
            auto &currentCapture = parsers.back();
            currentCapture.combType = CombType::OrEnd;

            if (!requireToken(tk, TokenType::CloseAngle)) {
                // TODO report error
                return;
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
    }
}

ParserList parseLogQlExpr(std::string const &expr) {
    std::vector<Parser> parsers;
    Tokenizer tokenizer { expr.c_str() };

    bool done = false;
    while (!done) {
        Token token = getToken(tokenizer);
        switch (token.type) {
            case TokenType::OpenAngle: {
                parseCapture(tokenizer, parsers);
                if(peekToken(tokenizer).type == TokenType::OpenAngle){
                    //TODO report error. Can't have two captures back to back
                    fprintf(stderr, "Invalid logQl expresion. Can't have captures back to back\n");
                    done = true;
                }
                break;
            }
            case TokenType::Literal: {
                parsers.push_back({ { { token.text, token.text + token.len } },
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
