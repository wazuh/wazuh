#include <algorithm>
#include <functional>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

bool parseFilePath(const char **it, char endToken) {
    const char *start = *it;
    while (**it != endToken) { (*it)++; }
    return true;
}

std::string parseAny(const char **it, char endToken) {
    const char *start = *it;
    while (**it != endToken) { (*it)++; }
    return { start, *it };
}

bool matchLiteral(const char **it, std::string /*the copy is intentional*/ literal) {
    // TODO Check if there's a better way to avoid the string copy + the remove algorithm
    literal.erase(std::remove(literal.begin(), literal.end(), '\\'), literal.end());
    int i = 0;
    for (; (**it) && (i < literal.size()); ++i) {
        if (**it != literal[i]) {
            return false;
        }
        (*it)++;
    }

    return literal[i] == '\0';
}

std::string parseJson(const char **it) {
    const char *start = *it;

    return "DUMMY";
};

bool parseTimeStamp(char **it, char endToken) {
    return true;
}

bool parseURI(char **it, char endToken) {
    return true;
}
