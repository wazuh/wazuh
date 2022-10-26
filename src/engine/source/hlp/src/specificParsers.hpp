#ifndef _H_SPECIFIC_PARSERS
#define _H_SPECIFIC_PARSERS

#include <string>
#include <unordered_map>
#include <vector>

#include "hlpDetails.hpp"

struct Parser;

/**
 * @brief Method to pre-configure a map parser at build stage to be used on
 * future to parse an event
 *
 * @param parser The map parser to be pre-configured
 * @param args List with the options for configuring the map parser
 * @return true on success. false on error
 */
bool configureKVMapParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method to pre-configure a TimeStamp parser at build stage to be used
 * on future to parse an event
 *
 * @param parser The TimeStamp parser to be pre-configured
 * @param args List with the options for configuring the TimeStamp parser
 * @return true on success. false on error
 */
bool configureTsParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method to pre-configure a Filepath parser at build stage to be used on
 * future to parse an event
 *
 * @param parser The Filepath parser to be pre-configured
 * @param args List with the options for configuring the Filepath parser
 * @return true on success. false on error
 */
bool configureFilepathParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method to pre-configure a Dpmain parser at build stage to be used on
 * future to parse an event
 *
 * @param parser The Domain parser to be pre-configured
 * @param args List with the options for configuring the Domain parser
 * @return true on success. false on error
 */
bool configureDomainParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method to preconfigure an Any parser, setting endToken to final char.
 * @return always true
 */
bool configureAnyParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method for pre-configuration of quoted string parsing
 * @param args if SIMPLE is used as a param it will use ' otherwise ""
 * @return always true
 */
bool configureQuotedString(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method for pre-configuration of boolean parsing
 * @param args the 'true' value to compare agains. (the 'true' string by
 * default)
 * @return always true
 */
bool configureBooleanParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method for pre-configure JSON parsing
 *
 * @param args json type format being the possibilities: "string", "bool", "number",
 * "object", "array", "null" or "any".
 * @return true if one of the possibles types was matched.
 * @throws std::runtime_error if args not in list or wrong quantity.
 */
bool configureJsonParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method for pre-configure a parser that will parse a string as CSV
 *
 * @param parser The parser to be pre-configured
 * @param args List with the destination field name of the CSV parser
 * @return true on success. false on error
 */
bool configureCSVParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Method to pre-configure a ignore parser at build stage to be used on future
 * to parse an event
 *
 * @param parser The ignore parser to be pre-configured
 * @param args List with the options for configuring the ignore parser
 * @return true on success. false on error
 * @throws std::runtime_error if args not in list or wrong quantity.
 */
bool configureIgnoreParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Parse an unspecified element until an endtoken character is found
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseAny(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a literal character
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool matchLiteral(const char** it, Parser const& parser, ParseResult&);

/**
 * @brief Parse a File path string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseFilePath(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a JSON string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseJson(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a map-like string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseKVMap(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse an IP string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseIPaddress(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a TimeStamp string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseTimeStamp(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse an url string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseURL(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a domain string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseDomain(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a user agent string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseUserAgent(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse an integer ir floating point number

 * @param it event for parsing.
 * @param result the number parsed
 * @return true for success false on error
 */
bool parseNumber(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief parse a quoted string
 * @param it event for parsing.
 * @param result string under quotes
 * @return true for success false on error
 */
bool parseQuotedString(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief parse a quoted string
 * @param it event for parsing.
 * @param result true if strings compares against configured trueval
 * @return true for success false on error
 */
bool parseBoolean(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a string until the next character (next token) is found. The parsed string
 * can be empty. Only fails if the next token is not found.
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false if the next token is not found.
 */
bool parseIgnore(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Configure xml parser.
 *
 * If no arguments are provided will use the default xml to json, if one argument is
 * provided will use the module specified in the argument with specific rules for
 * conversion.
 *
 * @param parser parser object
 * @param args arguments for the parser, one string argument or none.
 * @return true
 * @return false
 */
bool configureXmlParser(Parser& parser, std::vector<std::string_view> const& args);

/**
 * @brief Parse xml string and transform it to a json.
 *
 * For every xml node a json object is created and nested in the parent object.
 * For every xml attribute a key with \@<attribute_name> is created in the json
 * object. If the xml node has text content, a key with #text is created in the json
 * object. Every value is mapped as a string. Empty nodes or values are mapped to
 * empty strings.
 *
 * @param it event for parsing.
 * @param parser parser object
 * @param result JsonString
 * @return true
 * @return false
 */
bool parseXml(const char** it, Parser const& parser, ParseResult& result);

/**
 * @brief Parse a CSV like string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseCSV(const char** it, Parser const& parser, ParseResult& result);

#endif //_H_SPECIFIC_PARSERS
