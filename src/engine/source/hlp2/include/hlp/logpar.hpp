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
/**
 * @brief Schema types of fields
 *
 */
enum class SchemaType
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

constexpr auto schemaTypeToStr(SchemaType type)
{
    switch (type)
    {
        case SchemaType::IP: return "ip";
        case SchemaType::LONG: return "long";
        case SchemaType::OBJECT: return "object";
        case SchemaType::GEO_POINT: return "geo_point";
        case SchemaType::KEYWORD: return "keyword";
        case SchemaType::NESTED: return "nested";
        case SchemaType::SCALED_FLOAT: return "scaled_float";
        case SchemaType::TEXT: return "text";
        case SchemaType::BOOLEAN: return "boolean";
        case SchemaType::DATE: return "date";
        case SchemaType::FLOAT: return "float";
        default: return "error_type";
    }
}

constexpr auto strToSchemaType(std::string_view str)
{
    if (str == schemaTypeToStr(SchemaType::IP))
        return SchemaType::IP;
    if (str == schemaTypeToStr(SchemaType::LONG))
        return SchemaType::LONG;
    if (str == schemaTypeToStr(SchemaType::OBJECT))
        return SchemaType::OBJECT;
    if (str == schemaTypeToStr(SchemaType::GEO_POINT))
        return SchemaType::GEO_POINT;
    if (str == schemaTypeToStr(SchemaType::KEYWORD))
        return SchemaType::KEYWORD;
    if (str == schemaTypeToStr(SchemaType::NESTED))
        return SchemaType::NESTED;
    if (str == schemaTypeToStr(SchemaType::SCALED_FLOAT))
        return SchemaType::SCALED_FLOAT;
    if (str == schemaTypeToStr(SchemaType::TEXT))
        return SchemaType::TEXT;
    if (str == schemaTypeToStr(SchemaType::BOOLEAN))
        return SchemaType::BOOLEAN;
    if (str == schemaTypeToStr(SchemaType::DATE))
        return SchemaType::DATE;
    if (str == schemaTypeToStr(SchemaType::FLOAT))
        return SchemaType::FLOAT;
    return SchemaType::ERROR_TYPE;
}

/**
 * @brief Parser types
 *
 */
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

/**
 * @brief Holds the literal to build a literal parser
 *
 */
struct Literal
{
    std::string value;
    bool operator==(const Literal& other) const { return value == other.value; }
};

/**
 * @brief Holds the field name and indicates if it is a custom field
 *
 */
struct FieldName
{
    std::string value;
    bool custom;
    bool operator==(const FieldName& other) const
    {
        return value == other.value && custom == other.custom;
    }
};

/**
 * @brief Holds the field name, the arguments of the parsers and indicates if it is
 * optional
 *
 */
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

/**
 * @brief Holds the two fields of an optional expression
 *
 */
struct Choice
{
    Field left;
    Field right;
    bool operator==(const Choice& other) const
    {
        return left == other.left && right == other.right;
    }
};

/**
 * @brief Holds a list of ParserInfo to build an optional parser
 *
 */
struct Group
{
    std::list<std::variant<Literal, Field, Choice, Group>> children;
    bool operator==(const Group& other) const { return children == other.children; }
};

/**
 * @brief Return type of logpar parsers, it's a variant of all the possible
 * parsers to be built
 *
 */
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

/**
 * @brief Logpar manager, it holds the structures to obtain the parsers needed for the
 * different schema types and the parsers to build them.
 *
 */
class Logpar
{
private:
    using ParserBuilder = std::function<parsec::Parser<json::Json>(
        std::optional<std::string>, std::vector<std::string>)>;

    std::unordered_map<std::string, SchemaType> m_fieldTypes;
    std::unordered_map<SchemaType, ParserType> m_typeParsers;
    std::unordered_map<ParserType, ParserBuilder> m_parserBuilders;

    // build the parsers from the different parser info types
    parsec::Parser<json::Json> buildLiteralParser(const parser::Literal& literal) const;
    parsec::Parser<json::Json>
    buildFieldParser(const parser::Field& field,
                     std::optional<std::string> endToken = std::nullopt) const;
    parsec::Parser<json::Json>
    buildChoiceParser(const parser::Choice& choice,
                      std::optional<std::string> endToken = std::nullopt) const;
    parsec::Parser<json::Json> buildGroupOptParser(const parser::Group& group) const;
    parsec::Parser<json::Json>

    // build the parsers while adding the target field to the json
    buildParsers(const std::list<parser::ParserInfo>& parserInfos) const;

public:
    /**
     * @brief Construct a new Logpar object
     *
     * @param ecsFieldTypes a json object with the schema types of the schema fields
     * @throws std::runtime_error if errors occur while initializing
     */
    Logpar(const json::Json& ecsFieldTypes);

    /**
     * @brief Register a parser builder for the given parser type
     *
     * @param type the parser type
     * @param builder the parser builder
     * @throws std::runtime_error if the parser type is already registered
     */
    void registerBuilder(ParserType type, ParserBuilder builder);

    /**
     * @brief Build a parser for the given logpar expression
     *
     * The parser returned will return a json object with the parsed fields if any
     *
     * @param logpar the logpar expression
     * @return parsec::Parser<json::Json> the parser
     * @throws std::runtime_error if errors occur while building the parser
     */
    parsec::Parser<json::Json> build(std::string_view logpar) const;
};
} // namespace logpar
} // namespace hlp
#endif // _HLP_HPP
