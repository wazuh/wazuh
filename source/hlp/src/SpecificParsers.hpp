#ifndef _FILE_PATH_PARSER_H
#define _FILE_PATH_PARSER_H

#include <string>
#include <unordered_map>
#include <vector>

struct Parser;

bool configureMapParser(Parser &parser, std::vector<std::string_view> const& args);
bool configureTsParser(Parser &parser, std::vector<std::string_view> const& args);
bool configureFilepathParser(Parser &parser,
                             std::vector<std::string_view> const &args);
bool configureDomainParser(Parser &parser,
                             std::vector<std::string_view> const &args);

bool parseAny(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

bool matchLiteral(const char **it,
                  Parser const &parser,
                  std::unordered_map<std::string, std::string> &);

bool parseFilePath(const char **it,
                   Parser const &parser,
                   std::unordered_map<std::string, std::string> &result);

bool parseJson(const char **it,
               Parser const &parser,
               std::unordered_map<std::string, std::string> &result);

bool parseMap(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

bool parseIPaddress(const char **it,
                    Parser const &parser,
                    std::unordered_map<std::string, std::string> &result);

bool parseTimeStamp(const char **it,
                    Parser const &parser,
                    std::unordered_map<std::string, std::string> &result);

bool parseURL(const char **it,
              Parser const &parser,
              std::unordered_map<std::string, std::string> &result);

bool parseDomain(const char **it,
                 Parser const &parser,
                 std::unordered_map<std::string, std::string> &result);

bool parseUserAgent(const char **it,
                    Parser const &parser,
                    std::unordered_map<std::string, std::string> &result);

#endif //_FILE_PATH_PARSER_H
