#ifndef _H_SPECIFIC_PARSERS
#define _H_SPECIFIC_PARSERS

#include <string>
#include <unordered_map>
#include <vector>

struct Parser;

/**
 * @brief Method to pre-configure a map parser at build stage to be used on
 * future to parse an event
 *
 * @param parser The map parser to be pre-configured
 * @param args List with the options for configuring the map parser
 * @return true on success. false on error
 */
bool configureMapParser(Parser &parser,
                        std::vector<std::string_view> const &args);

/**
 * @brief Method to pre-configure a TimeStamp parser at build stage to be used
 * on future to parse an event
 *
 * @param parser The TimeStamp parser to be pre-configured
 * @param args List with the options for configuring the TimeStamp parser
 * @return true on success. false on error
 */
bool configureTsParser(Parser &parser,
                       std::vector<std::string_view> const &args);

/**
 * @brief Method to pre-configure a Filepath parser at build stage to be used on
 * future to parse an event
 *
 * @param parser The Filepath parser to be pre-configured
 * @param args List with the options for configuring the Filepath parser
 * @return true on success. false on error
 */
bool configureFilepathParser(Parser &parser,
                             std::vector<std::string_view> const &args);

/**
 * @brief Method to pre-configure a Dpmain parser at build stage to be used on
 * future to parse an event
 *
 * @param parser The Domain parser to be pre-configured
 * @param args List with the options for configuring the Domain parser
 * @return true on success. false on error
 */
bool configureDomainParser(Parser &parser,
                           std::vector<std::string_view> const &args);

/**
 * @brief Method to preconfigure an Any parser, setting endToken to final char.
* @return always true
 */
bool configureAnyParser(Parser &parser,
                           std::vector<std::string_view> const &args);
/**
 * @brief Method to pre-configure the any parser for Keyword parsing, this is
 * everything till the first empty space
* @return always true
 */
bool configureKeywordParser(Parser &parser,
                           std::vector<std::string_view> const &args);

/**
 * @brief Method for pre-configuration of quoted string parsing
 * @param args if SIMPLE is used as a param it will use ' otherwise ""
* @return always true
 */
bool configureQuotedString(Parser &parser,
                           std::vector<std::string_view> const &args);
/**
 * @brief Parse an unspecified element until an endtoken character is found
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseAny(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse a literal character
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool matchLiteral(const char **it,
                  Parser const &parser,
                  std::unordered_map<std::string, std::string> &);

/**
 * @brief Parse a File path string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseFilePath(const char **it,
                   Parser const &parser,
                   std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse a JSON string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseJson(const char **it,
               Parser const &parser,
               std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse a map-like string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseMap(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse an IP string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseIPaddress(const char **it,
                    Parser const &parser,
                    std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse a TimeStamp string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseTimeStamp(const char **it,
                    Parser const &parser,
                    std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse an url string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseURL(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse a domain string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseDomain(const char **it,
                 Parser const &parser,
                 std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse a user agent string
 *
 * @param it Iterator pointing to the string to be parser
 * @param parser struct with the parser definitions
 * @param result map where the parsing result is added
 * @return true on success. false on error
 */
bool parseUserAgent(const char **it,
                    Parser const &parser,
                    std::unordered_map<std::string, std::string> &result);

/**
 * @brief Parse an integer ir floating point number

 * @param it event for parsing.
 * @param result the number parsed
 * @return true for success false on error
 */
bool parseNumber(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

/**
 * @brief parse a quoted string
 * @param it event fro parsing.
 * @param result string under quotes
 * @return true for success false on error
 */
bool parseQuotedString(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

#endif //_H_SPECIFIC_PARSERS
