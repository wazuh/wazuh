#include <algorithm>
#include <memory>
#include <stdio.h>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <curl/curl.h>

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

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
    // TODO: Implement a benchmark test comparing this approach and a possible more performant one:
    // With Nlohman Json library it's possible to validate a Json string without having to parse it (convert and allocate a json object).
    // Note: Callbacks on parse() are required to catch the end of the json if the string has trailing data.
    rapidjson::Document doc;
    if (doc.Parse<rapidjson::kParseStopWhenDoneFlag>(*it).HasParseError()) {
        // TODO error handling
        return {};
    }

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    doc.Accept(writer);

    *it += s.GetLength();
    return s.GetString();
};

std::string parseMap(const char **it, char endToken, std::vector<std::string> captureOpts) {
    size_t opts_size = captureOpts.size();
    if (opts_size < 3) {
        return {};
    }
    char tuples_separator = captureOpts[1][0];
    char values_separator = captureOpts[2][0];
    char map_finalizer = endToken;
    bool has_map_finalizer = false;
    if (opts_size > 3) {
        map_finalizer = captureOpts[3][0];
        has_map_finalizer = true;
    }

    const char *start = *it;
    while (**it != map_finalizer && **it != '\0') { (*it)++; }
    std::string map_str { start, (size_t)((*it) - start) };
    if (has_map_finalizer) {
        (*it)++;
    }

    rapidjson::Document output_doc;
    output_doc.SetObject();
    auto& allocator = output_doc.GetAllocator();

    size_t tuple_start_pos = 0;
    bool stop = false;
    bool error = false;
    while (!stop)
    {
        size_t separator_pos = map_str.find(values_separator, tuple_start_pos);
        if (separator_pos == std::string::npos) {
            stop = true;
            error = true;
            //TODO Log error: Missing Separator
            break;
        }
        size_t tuple_end_pos = map_str.find(tuples_separator, separator_pos);
        if (tuple_end_pos == std::string::npos) {
            // Map ended
            stop = true;
        }
        std::string key_str = map_str.substr(tuple_start_pos, separator_pos-tuple_start_pos);
        std::string value_str = map_str.substr(separator_pos+1, tuple_end_pos-(separator_pos+1));
        if (key_str.empty() || value_str.empty() )
        {
            stop = true;
            error = true;
            //TODO Log error: Empty map fields
            break;
        }
        tuple_start_pos = tuple_end_pos+1;

        output_doc.AddMember(
            rapidjson::Value(key_str.c_str(), allocator),
            rapidjson::Value(value_str.c_str(), allocator),
            allocator);
    }

    if (!error) {
        rapidjson::StringBuffer s;
        rapidjson::Writer<rapidjson::StringBuffer> writer(s);
        output_doc.Accept(writer);
        return s.GetString();
    }
    else {
        return {};
    }
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
        //TODO error handling
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
