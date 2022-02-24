#ifndef _FILE_PATH_PARSER_H
#define _FILE_PATH_PARSER_H

#include <string>
#include <vector>

struct URLResult{
    std::string domain;   //"url.domain": "keyword",
    std::string fragment; //"url.fragment": "keyword",
    std::string original; //"url.original": "keyword",
    std::string password; //"url.password": "keyword",
    std::string path;     //"url.path": "keyword",
    std::string port;     //"url.port": "long",
    std::string query;    //"url.query": "keyword",
    std::string scheme;   //"url.scheme": "keyword",
    std::string username; //"url.username": "keyword",
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

std::string parseAny(const char **it, char endToken);

bool matchLiteral(const char **it, std::string const& literal);

void parseFilePath(const char **it, char endToken, FilePathResult &result);

std::string parseJson(const char **it);

std::string parseMap(const char **it, char endToken, std::vector<std::string> const& captureOpts);

std::string parseIPaddress(const char **it, char endToken);

bool parseTimeStamp(const char **it, std::vector<std::string> const& opts, char endToken, TimeStampResult &tsr);

bool parseURL(const char **it, char endToken, URLResult &result);

bool parseDomain(const char **it, char endToken, std::vector<std::string> const& captureOpts, DomainResult &result);

#endif //_FILE_PATH_PARSER_H
