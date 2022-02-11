#ifndef _FILE_PATH_PARSER_H
#define _FILE_PATH_PARSER_H

#include <string>

bool parseFilePath(const char **it, char endToken);

std::string parseAny(const char **it, char endToken);
bool matchLiteral(const char **it, std::string literal);

std::string parseJson(const char **it);

bool parseTimeStamp(char **it, char endToken);

bool parseURI(char **it, char endToken);

#endif //_FILE_PATH_PARSER_H
