#include "logParser.hpp"

#include <stdexcept>
#include <cstdio>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <profile/profile.hpp>

#include <fmt/format.h>

namespace
{
struct Tokenizer
{
    const char* stream;
};

enum class TokenType
{
    _EndOfAscii = 256,
    OpenAngle,
    CloseAngle,
    QuestionMark,
    Literal,
    EndOfExpr,
    Unknown,
    Error,
};

struct Token
{
    const char* text;
    size_t len;
    TokenType type;
};
} // namespace

static Token getToken(Tokenizer& tk)
{
    const char* c = tk.stream++;

    switch (c[0])
    {
        case '<': return {"<", 1, TokenType::OpenAngle};
        case '>': return {">", 1, TokenType::CloseAngle};
        case '?': return {"?", 1, TokenType::QuestionMark};
        case '\0': return {nullptr, 0, TokenType::EndOfExpr};
        default:
        {
            bool escaped = false;
            while (tk.stream[0]
                   && (escaped || (tk.stream[0] != '<' && tk.stream[0] != '>')))
            {
                tk.stream++;
                escaped = tk.stream[0] == '\\';
            }
            return {c, static_cast<size_t>(tk.stream - c), TokenType::Literal};
        }
    }

    // TODO unreachable
    return {nullptr, 0, TokenType::Unknown};
}

static bool requireToken(Tokenizer& tk, TokenType req)
{
    return getToken(tk).type == req;
}

static Token peekToken(Tokenizer const& tk)
{
    Tokenizer tmp {tk.stream};
    return getToken(tmp);
}

static char peekChar(Tokenizer const& tk)
{
    return tk.stream[0];
}

static std::vector<std::string> splitSlashSeparatedField(std::string_view str)
{
    std::vector<std::string> ret;
    while (true)
    {
        auto pos = str.find('/');
        if (pos == str.npos)
        {
            break;
        }
        ret.emplace_back(str.substr(0, pos));
        str = str.substr(pos + 1);
    }

    if (!str.empty())
    {
        ret.emplace_back(str);
    }

    return ret;
}

static bool parseCapture(Tokenizer& tk, ExpressionList& expresions)
{
    // Available options: <name> || <?name> || <name1>?<name2>
    // Forbidden options: <name  || <name>? || TODO: <name><name>
    Token token = getToken(tk);
    bool optional = false;
    if (token.type == TokenType::QuestionMark)
    {
        optional = true;
        token = getToken(tk);
    }

    if (token.type == TokenType::Literal)
    {
        expresions.push_back({{token.text, token.len}, ExpressionType::Capture});

        if (!requireToken(tk, TokenType::CloseAngle))
        {
            return false;
        }

        // TODO check if there's a better way to do this
        if (optional)
        {
            expresions.back().type = ExpressionType::OptionalCapture;
        }

        if (peekToken(tk).type == TokenType::QuestionMark)
        {
            // We are parsing <name1>?<name2>
            // Discard the peeked '?'
            getToken(tk);

            if (!requireToken(tk, TokenType::OpenAngle))
            {
                return false;
            }

            Token orEnd = getToken(tk);
            expresions.push_back({{orEnd.text, orEnd.len}, ExpressionType::Capture});

            if (!requireToken(tk, TokenType::CloseAngle))
            {
                return false;
            }

            char endToken = peekChar(tk);
            auto& currentCapture = expresions.back();
            currentCapture.endToken = endToken;
            // Fix up the combType of the previous capture as this is now an OR
            auto& prevCapture = expresions.at(expresions.size() - 2);
            prevCapture.type = ExpressionType::OrCapture;
            prevCapture.endToken = endToken;
        }
        else
        {
            // TODO Check if there's a better way to do this
            expresions.back().endToken = peekChar(tk);
        }
    }
    else
    {
        return false;
    }

    return true;
}

ExpressionList parseLogExpr(const char* expr)
{
    // <source.ip>
    WAZUH_TRACE_FUNCTION;
    ExpressionList expresions;
    Tokenizer tokenizer {expr};
    bool done = false;
    while (!done)
    {
        Token token = getToken(tokenizer);
        switch (token.type)
        {
            case TokenType::OpenAngle:
            {
                const char* prev = tokenizer.stream - 1;

                if (!parseCapture(tokenizer, expresions))
                {
                    throw std::runtime_error(
                        fmt::format("Invalid Logpar expression at \"{}\". Unable to "
                                    "parse capture expression",
                                    std::string(prev)));
                }

                break;
            }
            // This is the case when a "CloseAngle" is just used as a literal
            case TokenType::CloseAngle:
            case TokenType::Literal:
            {
                expresions.push_back({{token.text, token.len}, ExpressionType::Literal});
                break;
            }
            case TokenType::EndOfExpr:
            {
                done = true;
                break;
            }
            default:
            {
                throw std::runtime_error(
                    fmt::format("Invalid token type from \"{}\".", token.text));
            }
        }
    }

    return expresions;
}
