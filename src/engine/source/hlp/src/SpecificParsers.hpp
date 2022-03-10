#ifndef _FILE_PATH_PARSER_H
#define _FILE_PATH_PARSER_H

#include <string>
#include <unordered_map>
#include <vector>

struct Parser;

/**
 * @brief Method to pre-configure a map parser at build stage to be used on future to parse an event
 *
 * @param parser The map parser to be pre-configured
 * @param args List with the options for configuring the map parser
 * @return true on success. false on error
 */
bool configureMapParser(Parser &parser, std::vector<std::string_view> const& args);

/**
 * @brief Method to pre-configure a TimeStamp parser at build stage to be used on future to parse an event
 *
 * @param parser The TimeStamp parser to be pre-configured
 * @param args List with the options for configuring the TimeStamp parser
 * @return true on success. false on error
 */
bool configureTsParser(Parser &parser, std::vector<std::string_view> const& args);

/**
 * @brief Method to pre-configure a Filepath parser at build stage to be used on future to parse an event
 *
 * @param parser The Filepath parser to be pre-configured
 * @param args List with the options for configuring the Filepath parser
 * @return true on success. false on error
 */
bool configureFilepathParser(Parser &parser,
                             std::vector<std::string_view> const &args);

/**
 * @brief Method to pre-configure a Dpmain parser at build stage to be used on future to parse an event
 *
 * @param parser The Domain parser to be pre-configured
 * @param args List with the options for configuring the Domain parser
 * @return true on success. false on error
 */
bool configureDomainParser(Parser &parser,
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

#endif //_FILE_PATH_PARSER_H
