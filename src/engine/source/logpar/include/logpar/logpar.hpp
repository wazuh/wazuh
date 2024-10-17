#ifndef _LOGPAR_HPP
#define _LOGPAR_HPP

#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include <base/json.hpp>
#include <hlp/hlp.hpp>
#include <parsec/parsec.hpp>
#include <schemf/ischema.hpp>

namespace hlp
{
/**
 * @brief Schema types of fields
 *
 */
enum class SchemaType
{
    // Numeric types
    LONG,
    DOUBLE,
    FLOAT,
    SCALED_FLOAT,
    BYTE,
    // String types
    KEYWORD,
    TEXT,
    WILDCARD,
    // Other types
    BOOLEAN,
    IP,
    OBJECT,
    GEO_POINT,
    NESTED,
    DATE,
    // Special types, not in schema
    USER_AGENT,
    URL,
    // Error type
    ERROR_TYPE
};

constexpr auto schemaTypeToStr(SchemaType type)
{
    switch (type)
    {
        case SchemaType::LONG: return "long";
        case SchemaType::DOUBLE: return "double";
        case SchemaType::FLOAT: return "float";
        case SchemaType::SCALED_FLOAT: return "scaled_float";
        case SchemaType::BYTE: return "byte";
        case SchemaType::KEYWORD: return "keyword";
        case SchemaType::TEXT: return "text";
        case SchemaType::WILDCARD: return "wildcard";
        case SchemaType::BOOLEAN: return "boolean";
        case SchemaType::IP: return "ip";
        case SchemaType::OBJECT: return "object";
        case SchemaType::GEO_POINT: return "geo_point";
        case SchemaType::NESTED: return "nested";
        case SchemaType::DATE: return "date";
        case SchemaType::USER_AGENT: return "useragent";
        case SchemaType::URL: return "url";
        default: return "error_type";
    }
}

constexpr auto strToSchemaType(std::string_view str)
{
    if (str == schemaTypeToStr(SchemaType::LONG))
        return SchemaType::LONG;
    if (str == schemaTypeToStr(SchemaType::DOUBLE))
        return SchemaType::DOUBLE;
    if (str == schemaTypeToStr(SchemaType::FLOAT))
        return SchemaType::FLOAT;
    if (str == schemaTypeToStr(SchemaType::SCALED_FLOAT))
        return SchemaType::SCALED_FLOAT;
    if (str == schemaTypeToStr(SchemaType::BYTE))
        return SchemaType::BYTE;
    if (str == schemaTypeToStr(SchemaType::KEYWORD))
        return SchemaType::KEYWORD;
    if (str == schemaTypeToStr(SchemaType::TEXT))
        return SchemaType::TEXT;
    if (str == schemaTypeToStr(SchemaType::WILDCARD))
        return SchemaType::WILDCARD;
    if (str == schemaTypeToStr(SchemaType::BOOLEAN))
        return SchemaType::BOOLEAN;
    if (str == schemaTypeToStr(SchemaType::IP))
        return SchemaType::IP;
    if (str == schemaTypeToStr(SchemaType::OBJECT))
        return SchemaType::OBJECT;
    if (str == schemaTypeToStr(SchemaType::GEO_POINT))
        return SchemaType::GEO_POINT;
    if (str == schemaTypeToStr(SchemaType::NESTED))
        return SchemaType::NESTED;
    if (str == schemaTypeToStr(SchemaType::DATE))
        return SchemaType::DATE;
    if (str == schemaTypeToStr(SchemaType::USER_AGENT))
        return SchemaType::USER_AGENT;
    if (str == schemaTypeToStr(SchemaType::URL))
        return SchemaType::URL;
    return SchemaType::ERROR_TYPE;
}

/**
 * @brief Parser types
 *
 */
enum class ParserType
{
    // Enconding
    P_BINARY,
    // Error type
    ERROR_TYPE,
    // Format
    P_CSV,
    P_DSV,
    P_JSON,
    P_KV,
    P_XML,
    // Numeric
    P_BYTE,
    P_DOUBLE,
    P_FLOAT,
    P_LONG,
    P_SCALED_FLOAT,
    // Other types
    P_ALPHANUMERIC,
    P_BOOL,
    P_DATE,
    P_FILE,
    P_FQDN,
    P_IGNORE,
    P_IP,
    P_URI,
    P_USER_AGENT,
    // String
    P_BETWEEN,
    P_LITERAL,
    P_QUOTED,
    P_TEXT
};

constexpr auto parserTypeToStr(ParserType type)
{
    switch (type)
    {
        case ParserType::P_ALPHANUMERIC: return "alphanumeric";
        case ParserType::P_BETWEEN: return "between";
        case ParserType::P_BINARY: return "binary";
        case ParserType::P_BOOL: return "bool";
        case ParserType::P_BYTE: return "byte";
        case ParserType::P_CSV: return "csv";
        case ParserType::P_DATE: return "date";
        case ParserType::P_DOUBLE: return "double";
        case ParserType::P_DSV: return "dsv";
        case ParserType::P_FILE: return "file";
        case ParserType::P_FLOAT: return "float";
        case ParserType::P_FQDN: return "fqdn";
        case ParserType::P_IGNORE: return "ignore";
        case ParserType::P_IP: return "ip";
        case ParserType::P_JSON: return "json";
        case ParserType::P_KV: return "kv";
        case ParserType::P_LITERAL: return "literal";
        case ParserType::P_LONG: return "long";
        case ParserType::P_QUOTED: return "quoted";
        case ParserType::P_SCALED_FLOAT: return "scaled_float";
        case ParserType::P_TEXT: return "text";
        case ParserType::P_URI: return "uri";
        case ParserType::P_USER_AGENT: return "useragent";
        case ParserType::P_XML: return "xml";
        default: return "error_type";
    }
}

constexpr auto strToParserType(std::string_view str)
{
    if (str == parserTypeToStr(ParserType::P_LONG))
        return ParserType::P_LONG;
    if (str == parserTypeToStr(ParserType::P_DOUBLE))
        return ParserType::P_DOUBLE;
    if (str == parserTypeToStr(ParserType::P_FLOAT))
        return ParserType::P_FLOAT;
    if (str == parserTypeToStr(ParserType::P_SCALED_FLOAT))
        return ParserType::P_SCALED_FLOAT;
    if (str == parserTypeToStr(ParserType::P_BYTE))
        return ParserType::P_BYTE;
    if (str == parserTypeToStr(ParserType::P_TEXT))
        return ParserType::P_TEXT;
    if (str == parserTypeToStr(ParserType::P_LITERAL))
        return ParserType::P_LITERAL;
    if (str == parserTypeToStr(ParserType::P_QUOTED))
        return ParserType::P_QUOTED;
    if (str == parserTypeToStr(ParserType::P_BETWEEN))
        return ParserType::P_BETWEEN;
    if (str == parserTypeToStr(ParserType::P_BINARY))
        return ParserType::P_BINARY;
    if (str == parserTypeToStr(ParserType::P_CSV))
        return ParserType::P_CSV;
    if (str == parserTypeToStr(ParserType::P_DSV))
        return ParserType::P_DSV;
    if (str == parserTypeToStr(ParserType::P_JSON))
        return ParserType::P_JSON;
    if (str == parserTypeToStr(ParserType::P_XML))
        return ParserType::P_XML;
    if (str == parserTypeToStr(ParserType::P_KV))
        return ParserType::P_KV;
    if (str == parserTypeToStr(ParserType::P_BOOL))
        return ParserType::P_BOOL;
    if (str == parserTypeToStr(ParserType::P_USER_AGENT))
        return ParserType::P_USER_AGENT;
    if (str == parserTypeToStr(ParserType::P_IP))
        return ParserType::P_IP;
    if (str == parserTypeToStr(ParserType::P_DATE))
        return ParserType::P_DATE;
    if (str == parserTypeToStr(ParserType::P_URI))
        return ParserType::P_URI;
    if (str == parserTypeToStr(ParserType::P_FQDN))
        return ParserType::P_FQDN;
    if (str == parserTypeToStr(ParserType::P_FILE))
        return ParserType::P_FILE;
    if (str == parserTypeToStr(ParserType::P_IGNORE))
        return ParserType::P_IGNORE;
    if (str == parserTypeToStr(ParserType::P_ALPHANUMERIC))
        return ParserType::P_ALPHANUMERIC;
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
constexpr auto EXPR_WILDCARD = '~';
constexpr auto EXPR_FIELD_SEP = '.';
constexpr auto EXPR_FIELD_EXTENDED_CHARS_FIRST = "_@#~";
constexpr auto EXPR_FIELD_EXTENDED_CHARS = "_@#";
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
            return parsec::makeSuccess<T>({}, pos);
        return parsec::makeError<T>("Expected end of input", pos);
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
    bool operator==(const FieldName& other) const { return value == other.value; }
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

    // TODO: we should store this string instead of recreat it again?
    std::string toStr() const
    {
        return fmt::format("{}{}{}{}{}{}",
                           syntax::EXPR_BEGIN,
                           optional ? std::string {syntax::EXPR_OPT} : "",
                           name.value,
                           args.empty() ? "" : std::string {syntax::EXPR_ARG_SEP},
                           fmt::join(args, std::string {syntax::EXPR_ARG_SEP}),
                           syntax::EXPR_END);
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
    bool operator==(const Choice& other) const { return left == other.left && right == other.right; }
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
    using ParserBuilder = hlp::ParserBuilder;
    using Hlp = hlp::parser::Parser;

    std::shared_ptr<schemf::ISchema> m_schema;

    size_t m_maxGroupRecursion;

    size_t m_debugLvl;

    std::unordered_map<std::string, SchemaType> m_fieldTypes;
    std::unordered_map<SchemaType, ParserType> m_typeParsers;
    std::unordered_map<ParserType, ParserBuilder> m_parserBuilders;

    // build the parsers from the different parser info types
    Hlp buildLiteralParser(const parser::Literal& literal) const;
    Hlp buildFieldParser(const parser::Field& field, const std::vector<std::string>& endTokens = {}) const;
    Hlp buildChoiceParser(const parser::Choice& choice, const std::vector<std::string>& endTokens = {}) const;
    Hlp buildGroupOptParser(const parser::Group& group, size_t recurLvl) const;

    // build the parsers while adding the target field to the json
    Hlp buildParsers(const std::list<parser::ParserInfo>& parserInfos, size_t recurLvl) const;

public:
    /**
     * @brief Construct a new Logpar object
     *
     * @param ecsFieldTypes a json object with the schema types of the schema fields
     * @param schema the schema to validate the fields
     * @param maxGroupRecursion the maximum number of times a group can be nested
     * @param debugLvl the debug level
     *
     * @throws std::runtime_error if errors occur while initializing
     */
    Logpar(const json::Json& ecsFieldTypes,
           const std::shared_ptr<schemf::ISchema>& schema,
           size_t maxGroupRecursion = 1,
           size_t debugLvl = 0);

    /**
     * @brief Register a parser builder for the given parser type
     *
     * @param type the parser type
     * @param builder the parser builder
     * @throws std::runtime_error if the parser type is already registered
     */
    void registerBuilder(ParserType type, const ParserBuilder& builder);

    /**
     * @brief Build a parser for the given logpar expression
     *
     * The parser returned will return a json object with the parsed fields if any
     *
     * @param logpar the logpar expression
     * @return parsec::Parser<json::Json> the parser
     * @throws std::runtime_error if errors occur while building the parser
     */
    Hlp build(std::string_view logpar) const;
};
} // namespace logpar
} // namespace hlp
#endif // _HLP_HPP
