#ifndef _FILE_PATH_PARSER_H
#define _FILE_PATH_PARSER_H

#include <string>
#include <vector>

struct URLResult {
    std::string domain;
    std::string fragment;
    std::string original;
    std::string password;
    std::string path;
    std::string port;
    std::string query;
    std::string scheme;
    std::string username;
};

struct TimeStampResult {
    std::string year;
    std::string month;
    std::string day;
    std::string hour;
    std::string minutes;
    std::string seconds;
    std::string timezone;
};

// TODO Define which of this fields is really desirable for the response.
struct DomainResult{
    std::string protocol;
    std::string subdomain;
    std::string top_level_domain;
    std::string domain;
    std::string address;
    std::string registered_domain;
    std::string route;
};
struct FilePathResult{
    std::string path;           //"file.path": "keyword",
    std::string drive_letter;   //"file.drive_letter": "keyword",
    std::string folder;         //"file.directory": "keyword",
    std::string name;           //"file.name": "keyword",
    std::string extension;      //"file.extension": "keyword",
};

struct UserAgentResult
{
    std::string original;
};

std::string parseAny(const char **it, char endToken);

bool matchLiteral(const char **it, std::string const& literal);

void parseFilePath(const char **it, char endToken, std::vector<std::string> const& captureOpts, FilePathResult &result);

std::string parseJson(const char **it);

std::string parseMap(const char **it, char endToken, std::vector<std::string> const& captureOpts);

std::string parseIPaddress(const char **it, char endToken);

bool parseTimeStamp(const char **it, std::vector<std::string> const& opts, char endToken, TimeStampResult &tsr);

bool parseURL(const char **it, char endToken, URLResult &result);

bool parseDomain(const char **it, char endToken, std::vector<std::string> const& captureOpts, DomainResult &result);

bool parseUserAgent(const char** it, char endToken, UserAgentResult& ret);

#endif //_FILE_PATH_PARSER_H
