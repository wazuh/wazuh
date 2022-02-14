#include <algorithm>
#include <memory>
#include <stdio.h>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <curl/curl.h>

#include "SpecificParsers.hpp"

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

bool matchLiteral(const char **it, std::string const& literal) {
    int i = 0;
    for (; (**it) && (i < literal.size());) {
        // Skip over the escaping '\'
        if (**it == '\\') {
            continue;
        }

        if (**it != literal[i]) {
            return false;
        }

        (*it)++;
        i++;
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

bool parseURL(const char **it, char endToken, URLResult &result) {
    const char *start = *it;
    // TODO Check how to handle if the URL contains the endToken
    while (**it != endToken) { (*it)++; }

    auto urlCleanup = [](auto *url) { curl_url_cleanup(url); };
    std::unique_ptr<CURLU, decltype(urlCleanup)> url { curl_url(), urlCleanup };

    if (url == nullptr) {
        // TODO error
        return false;
    }

    std::string urlStr { start, *it };
    auto uc = curl_url_set(url.get(), CURLUPART_URL, urlStr.c_str(), 0);
    if (uc) {
        fprintf(stderr, "Error setting URL to parse: [%s]\n", curl_url_strerror(uc));
        return false;
    }

    // TODO curl will parse and copy the URL into an allocated
    // char ptr and we will copy it again into the string for the result
    // Check if there's a way to avoid all the copying here
    char *str;
    uc = curl_url_get(url.get(), CURLUPART_URL, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.original = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_HOST, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.domain = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_PATH, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.path = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_SCHEME, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.scheme = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_USER, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.username = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_PASSWORD, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.password = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_QUERY, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.query = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_PORT, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.port = str;
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_FRAGMENT, &str, 0);
    if (uc) {
        // TODO set an error someway
        return false;
    }
    result.fragment = str;
    curl_free(str);

    return true;
}
