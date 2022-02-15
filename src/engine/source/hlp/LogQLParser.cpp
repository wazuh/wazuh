#include <algorithm>
#include <functional>
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
    { "timestamp", ParserType::Keyword },
    { "http.request.method", ParserType::Keyword },
    { "JSON", ParserType::Json},
};

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
