#include <algorithm>
#include <arpa/inet.h>
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

std::string parseIPaddress(const char **it, char endToken) {
    struct in_addr ip;
    struct in6_addr ipv6;
    const char *start = *it;
    while (**it != 0 && **it != endToken) { (*it)++; }
    std::string srcip { start, (size_t)((*it) - start) };

    if(inet_pton(AF_INET,srcip.c_str(), &ip)) {
        return srcip;
    }
    else if(inet_pton(AF_INET6,srcip.c_str(), &ipv6)) {
        return srcip;
    }
    else {
        return {};
    }
}

bool parseTimeStamp(char **it, char endToken) {
    return true;
}

bool parseURI(char **it, char endToken) {
    return true;
}
