#ifndef _FILE_PATH_PARSER_H
#define _FILE_PATH_PARSER_H

#include <string>

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

bool parseFilePath(const char **it, char endToken);

std::string parseAny(const char **it, char endToken);
bool matchLiteral(const char **it, std::string const& literal);

std::string parseJson(const char **it);

std::string parseIPaddress(const char **it, char endToken);

bool parseTimeStamp(char **it, char endToken);

bool parseURL(const char **it, char endToken, URLResult &result);

#endif //_FILE_PATH_PARSER_H
