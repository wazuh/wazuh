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

enum class TimeStampFormat {
    ANSIC,
    Layout,
    UnixDate,
    ANSICM,
    APACHE,
    RubyDate,
    RFC822,
    RFC822Z,
    RFC850,
    RFC1123Z,
    RFC1123,
    RFC3339Nano,
    RFC3339,
    StampNano,
    StampMicro,
    StampMilli,
    Stamp,
    Kitchen,
    NONE,
};

struct TimeStampResult {
    std::string year;
    std::string month;
    std::string day;
    std::string hour;
    std::string minutes;
    std::string seconds;
};

bool parseFilePath(const char **it, char endToken);

std::string parseAny(const char **it, char endToken);

bool matchLiteral(const char **it, std::string const& literal);

std::string parseJson(const char **it);

std::string parseMap(const char **it, char endToken, std::vector<std::string> const& captureOpts);

std::string parseIPaddress(const char **it, char endToken);

bool parseTimeStamp(const char **it, char endToken, TimeStampResult &tsr);

bool parseURL(const char **it, char endToken, URLResult &result);

#endif //_FILE_PATH_PARSER_H
