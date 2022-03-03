#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "LogQLParser.hpp"
#include "hlpDetails.hpp"

using namespace LogQL;

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

static Element parseField(Token token) {
    // TODO assert token type
    // TODO report errors
    //std::vector<std::string> captureParams;

    // We could be parsing:
    //      '<_>'
    //      '<_name>'
    //      '<_name/type>'
    //      '<_name/type/type2>'
    std::string parameters = { token.text, token.len };
    auto pos = parameters.find('/');
    Element element;
    element.combType = Comb::Null;
    element.endToken = 0;
    element.name = parameters.substr(0, pos);
    element.opts = parameters.substr(pos+1);
    element.type = Type::field;
    if (token.text[0] == '_') {
        element.isTemp = true;
        auto pos = element.opts.find('/');
        element.parser = element.opts.substr(0, pos);
        element.opts = element.opts.substr(pos+1);
    }
    else {
        element.parser = element.name;
    }

    return element;
}


static bool parseCapture(Tokenizer &tk, ElementList &elements) {
    //<name> || <?name> || <name1>?<name2>
    Token token = getToken(tk);
    bool optional = false;
    if (token.type == TokenType::QuestionMark) {
        optional = true;
        token = getToken(tk);
    }

    if (token.type == TokenType::Literal) {
        elements.emplace_back(parseField(token));

        if (!requireToken(tk, TokenType::CloseAngle)) {
            // TODO report parsing error
            return false;
        }

        // TODO check if there's a better way to do this
        if (optional) {
            elements.back().combType = Comb::Optional;
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
            auto &prevCapture = elements.back();
            prevCapture.combType = Comb::Or;

            elements.emplace_back(parseField(getToken(tk)));
            auto &currentCapture = elements.back();
            currentCapture.combType = Comb::OrEnd;

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
            elements.back().endToken = peekChar(tk);
        }
    }
    else {
        // TODO error
        return false;
    }

    return true;
}

ElementList LogQL::parseExpr(std::string const &expr) {
    ElementList elements;
    Tokenizer tokenizer { expr.c_str() };

    bool done = false;
    while (!done) {
        Token token = getToken(tokenizer);
        switch (token.type) {
            case TokenType::OpenAngle: {
                const char *prev = tokenizer.stream - 1;

                if (!parseCapture(tokenizer, elements)) {
                    // TODO report error
                    //  Reset the parser list to signify an error occurred
                    elements.clear();
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
                    elements.clear();
                    done = true;
                }
                break;
            }

            case TokenType::Literal: {
                elements.push_back({ {},
                                    { token.text, token.text + token.len },
                                    {},
                                    Type::Literal,
                                    Comb::Null,
                                    0,
                                    false });
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

    return elements;
}
