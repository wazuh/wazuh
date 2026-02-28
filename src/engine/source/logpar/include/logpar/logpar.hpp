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
    P_HALF_FLOAT,
    P_INTEGER,
    P_LONG,
    P_SCALED_FLOAT,
    P_SHORT,
    P_UNSIGNED_LONG,
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

/**
 * @brief Convert a ParserType to its string representation.
 *
 * @param type The parser type.
 * @return constexpr const char* The string name, or "error_type" for unknown.
 */
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
        case ParserType::P_HALF_FLOAT: return "half_float";
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
        case ParserType::P_UNSIGNED_LONG: return "unsigned_long";
        case ParserType::P_INTEGER: return "integer";
        case ParserType::P_SHORT: return "short";
        default: return "error_type";
    }
}

/**
 * @brief Convert a string to a ParserType.
 *
 * @param str The parser type name.
 * @return ParserType The corresponding parser type, or ERROR_TYPE if unknown.
 */
constexpr auto strToParserType(std::string_view str)
{
    if (str == parserTypeToStr(ParserType::P_LONG))
        return ParserType::P_LONG;
    if (str == parserTypeToStr(ParserType::P_DOUBLE))
        return ParserType::P_DOUBLE;
    if (str == parserTypeToStr(ParserType::P_FLOAT))
        return ParserType::P_FLOAT;
    if (str == parserTypeToStr(ParserType::P_HALF_FLOAT))
        return ParserType::P_HALF_FLOAT;
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
    if (str == parserTypeToStr(ParserType::P_UNSIGNED_LONG))
        return ParserType::P_UNSIGNED_LONG;
    if (str == parserTypeToStr(ParserType::P_INTEGER))
        return ParserType::P_INTEGER;
    if (str == parserTypeToStr(ParserType::P_SHORT))
        return ParserType::P_SHORT;
    return ParserType::ERROR_TYPE;
}

namespace logpar
{
/**
 * @brief Syntax characters used by the logpar expression grammar.
 */
namespace syntax
{
constexpr auto EXPR_BEGIN = '<';                              ///< Start of a field expression.
constexpr auto EXPR_END = '>';                                ///< End of a field expression.
constexpr auto EXPR_OPT = '?';                                ///< Optional field marker.
constexpr auto EXPR_ESCAPE = '\\';                            ///< Escape character.
constexpr auto EXPR_ARG_SEP = '/';                            ///< Argument separator.
constexpr auto EXPR_GROUP_BEGIN = '(';                        ///< Start of a group expression.
constexpr auto EXPR_GROUP_END = ')';                          ///< End of a group expression.
constexpr auto EXPR_WILDCARD = '~';                           ///< Wildcard character.
constexpr auto EXPR_FIELD_SEP = '.';                          ///< Field name separator.
constexpr auto EXPR_FIELD_EXTENDED_CHARS_FIRST = "_@#~";      ///< Extra chars allowed at start of a field name.
constexpr auto EXPR_FIELD_EXTENDED_CHARS = "_@#";             ///< Extra chars allowed in a field name.
}; // namespace syntax

/**
 * @brief Low-level parsec-based parsers for the logpar expression grammar.
 */
namespace parser
{
// Basic parsers

/**
 * @brief Parse a single character from the allowed set.
 *
 * @param chars Allowed characters.
 * @return parsec::Parser<char> A parser that matches one character from the set.
 */
parsec::Parser<char> pChar(std::string chars);

/**
 * @brief Parse a single character NOT in the given set.
 *
 * @param chars Disallowed characters.
 * @return parsec::Parser<char> A parser that matches one character not in the set.
 */
parsec::Parser<char> pNotChar(std::string chars);

/**
 * @brief Parse an escaped character.
 *
 * @param chars Characters that can be escaped.
 * @param esc The escape character.
 * @return parsec::Parser<char> A parser that matches an escaped character.
 */
parsec::Parser<char> pEscapedChar(std::string chars, char esc);

/**
 * @brief Parse a raw literal string (zero or more characters).
 *
 * @param reservedChars Characters that end the literal.
 * @param esc Escape character.
 * @return parsec::Parser<std::string> A parser for raw literal strings.
 */
parsec::Parser<std::string> pRawLiteral(std::string reservedChars, char esc);

/**
 * @brief Parse a non-empty raw literal string (one or more characters).
 *
 * @param reservedChars Characters that end the literal.
 * @param esc Escape character.
 * @return parsec::Parser<std::string> A parser for non-empty raw literal strings.
 */
parsec::Parser<std::string> pRawLiteral1(std::string reservedChars, char esc);

/**
 * @brief Parse a single alphanumeric character, optionally including extended characters.
 *
 * @param extended Additional allowed characters (default: "").
 * @return parsec::Parser<char> A parser for alphanumeric characters.
 */
parsec::Parser<char> pCharAlphaNum(std::string extended = "");

/**
 * @brief Parse end-of-input. Succeeds only when the input is fully consumed.
 *
 * @tparam T The result type.
 * @return parsec::Parser<T> A parser that succeeds at end-of-input.
 */
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

    /**
     * @brief Convert the field expression back to its string representation.
     *
     * @return std::string The logpar field expression string.
     */
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

/** @brief Parse a literal token. */
parsec::Parser<Literal> pLiteral();

/** @brief Parse parser arguments (slash-separated list). */
parsec::Parser<parsec::Values<std::string>> pArgs();
/** @brief Parse a field name. */
parsec::Parser<FieldName> pFieldName();
/** @brief Parse a complete field expression. */
parsec::Parser<Field> pField();

/** @brief Parse a choice expression (two optional fields). */
parsec::Parser<Choice> pChoice();

/** @brief Parse a sequence of logpar expressions. */
parsec::Parser<parsec::Values<ParserInfo>> pExpr();

/** @brief Parse a grouped (optional) expression. */
parsec::Parser<Group> pGroup();

/** @brief Parse a complete logpar expression string. */
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

    size_t m_maxGroupRecursion;
    size_t m_debugLvl;
    std::weak_ptr<schemf::ISchema> m_schema;
    std::unordered_map<schemf::Type, ParserType> m_typeParsers;
    std::unordered_map<ParserType, ParserBuilder> m_parserBuilders;
    std::unordered_map<std::string, ParserType> m_fieldParserOverrides;

    // build the parsers from the different parser info types

    /**
     * @brief Build a parser from a literal token.
     *
     * @param literal The literal info.
     * @return Hlp The constructed parser.
     */
    Hlp buildLiteralParser(const parser::Literal& literal) const;

    /**
     * @brief Build a parser from a field expression.
     *
     * @param field The field info.
     * @param endTokens Optional end tokens that delimit the field value.
     * @return Hlp The constructed parser.
     */
    Hlp buildFieldParser(const parser::Field& field, const std::vector<std::string>& endTokens = {}) const;

    /**
     * @brief Build a parser from a choice expression.
     *
     * @param choice The choice info.
     * @param endTokens Optional end tokens.
     * @return Hlp The constructed parser.
     */
    Hlp buildChoiceParser(const parser::Choice& choice, const std::vector<std::string>& endTokens = {}) const;

    /**
     * @brief Build a parser from a group (optional) expression.
     *
     * @param group The group info.
     * @param recurLvl Current recursion level.
     * @return Hlp The constructed parser.
     */
    Hlp buildGroupOptParser(const parser::Group& group, size_t recurLvl) const;

    /**
     * @brief Build the combined parser from a list of parser infos.
     *
     * @param parserInfos List of parsed logpar tokens.
     * @param recurLvl Current recursion level.
     * @return Hlp The combined parser.
     */
    Hlp buildParsers(const std::list<parser::ParserInfo>& parserInfos, size_t recurLvl) const;

    /**
     * @brief Get the Schema object
     *
     * @return std::shared_ptr<schemf::ISchema>
     * @throws std::runtime_error if the schema is not available
     */
    inline std::shared_ptr<schemf::ISchema> getSchema() const
    {
        auto schema = m_schema.lock();
        if (!schema)
        {
            throw std::runtime_error("Logpar tried to get schema but it was not available");
        }

        return schema;
    }

    /**
     * @brief Get the Parser object for the given field
     *
     * @param field the field to get the parser
     * @return ParserType
     *
     * @throws std::runtime_error if the parser is not found or not supported
     */
    inline ParserType getParser(const std::string& field) const
    {
        // Return override if it exists
        if (m_fieldParserOverrides.count(field) != 0)
        {
            return m_fieldParserOverrides.at(field);
        }

        // Get the type from the schema table otherwise
        auto schema = getSchema();
        auto type = schema->getType(field);
        if (m_typeParsers.count(type) == 0)
        {
            throw std::runtime_error(fmt::format(
                "Parser for ECS type '{}' not found, needed for field '{}'", schemf::typeToStr(type), field));
        }

        auto parserType = m_typeParsers.at(type);
        if (parserType == ParserType::ERROR_TYPE)
        {
            throw std::runtime_error(fmt::format(
                "Parser for ECS type '{}' not supported, needed for field '{}'", schemf::typeToStr(type), field));
        }

        return parserType;
    }

public:
    /**
     * @brief Construct a new Logpar object
     *
     * @param fieldParserOverrides a json object with overrides for the field parsers
     * @param schema the schema to validate the fields
     * @param maxGroupRecursion the maximum number of times a group can be nested
     * @param debugLvl the debug level
     *
     * @throws std::runtime_error if errors occur while initializing
     */
    Logpar(const json::Json& fieldParserOverrides,
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
