#ifndef _HLP_HPP
#define _HLP_HPP

#include <list>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace hlp
{
enum class EcsType
{
    IP,
    LONG,
    OBJECT,
    GEO_POINT,
    KEYWORD,
    NESTED,
    SCALED_FLOAT,
    TEXT,
    BOOLEAN,
    DATE,
    FLOAT,
    ERROR_TYPE
};

constexpr auto ecsTypeToStr(EcsType type)
{
    switch (type)
    {
        case EcsType::IP: return "ip";
        case EcsType::LONG: return "long";
        case EcsType::OBJECT: return "object";
        case EcsType::GEO_POINT: return "geo_point";
        case EcsType::KEYWORD: return "keyword";
        case EcsType::NESTED: return "nested";
        case EcsType::SCALED_FLOAT: return "scaled_float";
        case EcsType::TEXT: return "text";
        case EcsType::BOOLEAN: return "boolean";
        case EcsType::DATE: return "date";
        case EcsType::FLOAT: return "float";
        default: return "error_type";
    }
}

constexpr auto strToEcsType(std::string_view str)
{
    if (str == ecsTypeToStr(EcsType::IP))
        return EcsType::IP;
    if (str == ecsTypeToStr(EcsType::LONG))
        return EcsType::LONG;
    if (str == ecsTypeToStr(EcsType::OBJECT))
        return EcsType::OBJECT;
    if (str == ecsTypeToStr(EcsType::GEO_POINT))
        return EcsType::GEO_POINT;
    if (str == ecsTypeToStr(EcsType::KEYWORD))
        return EcsType::KEYWORD;
    if (str == ecsTypeToStr(EcsType::NESTED))
        return EcsType::NESTED;
    if (str == ecsTypeToStr(EcsType::SCALED_FLOAT))
        return EcsType::SCALED_FLOAT;
    if (str == ecsTypeToStr(EcsType::TEXT))
        return EcsType::TEXT;
    if (str == ecsTypeToStr(EcsType::BOOLEAN))
        return EcsType::BOOLEAN;
    if (str == ecsTypeToStr(EcsType::DATE))
        return EcsType::DATE;
    if (str == ecsTypeToStr(EcsType::FLOAT))
        return EcsType::FLOAT;
    return EcsType::ERROR_TYPE;
}

enum class ParserType
{
    P_BOOL,
    P_BYTE,
    P_LONG,
    P_FLOAT,
    P_DOUBLE,
    P_SCALED_FLOAT,
    P_TEXT,
    P_BINARY,
    P_DATE,
    P_IP,
    P_URI,
    P_LITERAL,
    ERROR_TYPE
};

constexpr auto parserTypeToStr(ParserType type)
{
    switch (type)
    {
        case ParserType::P_BOOL: return "bool";
        case ParserType::P_BYTE: return "byte";
        case ParserType::P_LONG: return "long";
        case ParserType::P_FLOAT: return "float";
        case ParserType::P_DOUBLE: return "double";
        case ParserType::P_SCALED_FLOAT: return "scaled_float";
        case ParserType::P_TEXT: return "text";
        case ParserType::P_BINARY: return "binary";
        case ParserType::P_DATE: return "date";
        case ParserType::P_IP: return "ip";
        case ParserType::P_URI: return "uri";
        case ParserType::P_LITERAL: return "literal";
        default: return "error_type";
    }
}

constexpr auto strToParserType(std::string_view str)
{
    if (str == parserTypeToStr(ParserType::P_BOOL))
        return ParserType::P_BOOL;
    if (str == parserTypeToStr(ParserType::P_BYTE))
        return ParserType::P_BYTE;
    if (str == parserTypeToStr(ParserType::P_LONG))
        return ParserType::P_LONG;
    if (str == parserTypeToStr(ParserType::P_FLOAT))
        return ParserType::P_FLOAT;
    if (str == parserTypeToStr(ParserType::P_DOUBLE))
        return ParserType::P_DOUBLE;
    if (str == parserTypeToStr(ParserType::P_SCALED_FLOAT))
        return ParserType::P_SCALED_FLOAT;
    if (str == parserTypeToStr(ParserType::P_TEXT))
        return ParserType::P_TEXT;
    if (str == parserTypeToStr(ParserType::P_BINARY))
        return ParserType::P_BINARY;
    if (str == parserTypeToStr(ParserType::P_DATE))
        return ParserType::P_DATE;
    if (str == parserTypeToStr(ParserType::P_IP))
        return ParserType::P_IP;
    if (str == parserTypeToStr(ParserType::P_URI))
        return ParserType::P_URI;
    if (str == parserTypeToStr(ParserType::P_LITERAL))
        return ParserType::P_LITERAL;
    return ParserType::ERROR_TYPE;
}

namespace logpar
{
namespace syntax
{
constexpr auto EXPR_BEGIN = '<';
constexpr auto EXPR_END = '>';
constexpr auto EXPR_OPT = '?';
constexpr auto EXPR_ESCAPE = '\\';
constexpr auto EXPR_ARG_SEP = '/';
constexpr auto EXPR_GROUP_BEGIN = '(';
constexpr auto EXPR_GROUP_END = ')';
constexpr auto EXPR_CUSTOM_FIELD = '~';
constexpr auto EXPR_FIELD_SEP = '.';
constexpr auto EXPR_FIELD_EXTENDED_CHARS = "_";
}; // namespace syntax

namespace parser
{
// Basic parsers
parsec::Parser<char> pChar(std::string chars);
parsec::Parser<char> pNotChar(std::string chars);
parsec::Parser<char> pEscapedChar(std::string chars, char esc);
parsec::Parser<std::string> pRawLiteral(std::string reservedChars, char esc);
parsec::Parser<std::string> pRawLiteral1(std::string reservedChars, char esc);
parsec::Parser<char> pCharAlphaNum(std::string extended = "");
template<typename T>
parsec::Parser<T> pEof()
{
    return [](std::string_view text, size_t pos)
    {
        if (pos == text.size())
            return parsec::makeSuccess<T>({}, text, pos);
        return parsec::makeError<T>("Expected end of input", text, pos);
    };
};

struct Literal
{
    std::string value;
    bool operator==(const Literal& other) const { return value == other.value; }
};

struct FieldName
{
    std::string value;
    bool custom;
    bool operator==(const FieldName& other) const
    {
        return value == other.value && custom == other.custom;
    }
};

struct Field
{
    FieldName name;
    std::list<std::string> args;
    bool optional;
    bool operator==(const Field& other) const
    {
        return name == other.name && args == other.args && optional == other.optional;
    }
};

struct Choice
{
    Field left;
    Field right;
    bool operator==(const Choice& other) const
    {
        return left == other.left && right == other.right;
    }
};

struct Group
{
    std::list<std::variant<Literal, Field, Choice, Group>> children;
    bool operator==(const Group& other) const { return children == other.children; }
};

using ParserInfo = std::variant<Literal, Field, Choice, Group>;

// Specific literal parser
parsec::Parser<Literal> pLiteral();

// Specific field parsers
parsec::Parser<parsec::Values<std::string>> pArgs();
parsec::Parser<FieldName> pFieldName();
parsec::Parser<Field> pField();

// Specific choice parser
parsec::Parser<Choice> pChoice();

// Expression parser
parsec::Parser<parsec::Values<ParserInfo>> pExpr();

// Specific group parser
parsec::Parser<Group> pGroup();

// Logpar parser
parsec::Parser<std::list<ParserInfo>> pLogpar();

}; // namespace parser

class Logpar
{
private:
    using ParserBuilder =
        std::function<parsec::Parser<json::Json>(std::optional<std::string>, std::vector<std::string>)>;

    std::unordered_map<std::string, EcsType> m_fieldTypes;
    std::unordered_map<EcsType, ParserType> m_typeParsers;
    std::unordered_map<ParserType, ParserBuilder> m_parserBuilders;

    parsec::Parser<json::Json> buildLiteralParser(const parser::Literal& literal) const;
    parsec::Parser<json::Json> buildFieldParser(const parser::Field& field,
                                                std::optional<std::string> endToken = std::nullopt) const;
    parsec::Parser<json::Json> buildChoiceParser(const parser::Choice& choice,
                                                 std::optional<std::string> endToken = std::nullopt) const;
    parsec::Parser<json::Json> buildGroupOptParser(const parser::Group& group) const;
    parsec::Parser<json::Json>
    buildParsers(const std::list<parser::ParserInfo>& parserInfos) const;

public:
    Logpar(const json::Json& ecsFieldTypes);

    void registerBuilder(ParserType type, ParserBuilder builder);

    parsec::Parser<json::Json> build(std::string_view logpar) const;
};
} // namespace logpar
} // namespace hlp
#endif // _HLP_HPP
