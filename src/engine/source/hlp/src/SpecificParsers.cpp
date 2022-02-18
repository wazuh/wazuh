#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>

#include "date/date.h"

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
}

std::string parseMap(const char **it, char endToken, std::vector<std::string> const& captureOpts) {
    size_t opts_size = captureOpts.size();
    if (opts_size < 2) {
        return {};
    }
    char tuples_separator = captureOpts[0][0];
    char values_separator = captureOpts[1][0];
    char map_finalizer = endToken;
    bool has_map_finalizer = false;
    if (opts_size > 2) {
        map_finalizer = captureOpts[2][0];
        has_map_finalizer = true;
    }

    const char *start = *it;
    while (**it != map_finalizer && **it != '\0') { (*it)++; }
    std::string_view map_str { start, (size_t)((*it) - start) };
    if (has_map_finalizer) {
        (*it)++;
    }

    rapidjson::Document output_doc;
    output_doc.SetObject();
    auto& allocator = output_doc.GetAllocator();

    size_t tuple_start_pos = 0;
    bool done = false;
    while (!done)
    {
        size_t separator_pos = map_str.find(values_separator, tuple_start_pos);
        if (separator_pos == std::string::npos) {
            //TODO Log error: Missing Separator
            break;
        }
        size_t tuple_end_pos = map_str.find(tuples_separator, separator_pos);
        std::string key_str(map_str.substr(tuple_start_pos, separator_pos-tuple_start_pos));
        std::string value_str(map_str.substr(separator_pos+1, tuple_end_pos-(separator_pos+1)));

        if (key_str.empty() || value_str.empty() )
        {
            //TODO Log error: Empty map fields
            break;
        }
        else if (tuple_end_pos == std::string::npos) {
            // Map ended
            done = true;
        }
        tuple_start_pos = tuple_end_pos+1;

        output_doc.AddMember(
            rapidjson::Value(key_str.c_str(), allocator),
            rapidjson::Value(value_str.c_str(), allocator),
            allocator);
    }

    if (done) {
        rapidjson::StringBuffer s;
        rapidjson::Writer<rapidjson::StringBuffer> writer(s);
        output_doc.Accept(writer);
        return s.GetString();
    }
    else {
        return {};
    }
}

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


/* */

//TODO: force an specific format (e.g. <timestamp/APACHE>)
//TODO: using a fromat string like get_time.
bool parseTimeStamp(const char **it, char endToken, TimeStampResult &tsr) {
    using namespace date;

    sys_time<std::chrono::microseconds> tp;

    const std::unordered_map<TimeStampFormat,std::string> TimeStampFormatMapper {
        {TimeStampFormat::ANSICM     ,"%a %b _%d %H:%M:%S.123456 %Y"},  // microseconds pending
        {TimeStampFormat::Layout     ,"%d/%m %H:%M:%S '%y %z"},
        {TimeStampFormat::UnixDate   ,"%a %b _%d %H:%M:%S %Z %Y"},
        {TimeStampFormat::ANSIC      ,"%a %b _%d %H:%M:%S %Y"},
        {TimeStampFormat::APACHE     ,"%a %b _%d %T %Y"},               // need to check one or the other
        {TimeStampFormat::RubyDate   ,"%a %b %d %H:%M:%S %z %Y"},
        {TimeStampFormat::RFC822     ,"%d %b %y %H:%M %Z"},
        {TimeStampFormat::RFC822Z    ,"%d %b %Ey %H:%M:%S %z"},
        {TimeStampFormat::RFC850     ,"%A, %d-%b-%y %H:%M:%S %Z"},
        {TimeStampFormat::RFC1123Z   ,"%a, %d %b %Y %T %z"},
        {TimeStampFormat::RFC1123    ,"%a, %d %b %Y %T %Z"},
        {TimeStampFormat::RFC3339Nano,"%Y-%m-%dT%H:%M:%S.999999999Z%Ez"},       // microseconds pending
        {TimeStampFormat::RFC3339    ,"%Y-%m-%dT%H:%M:%SZ%Ez"},
        {TimeStampFormat::StampNano  ,"%b _%d %H:%M:%S.000000000"},             // nano seconds pending
        {TimeStampFormat::StampMicro ,"%b _%d %H:%M:%S.000000"},                // microseconds pending
        {TimeStampFormat::StampMilli ,"%b _%d %H:%M:%S.000"},                   // mili seconds pending
        {TimeStampFormat::Stamp      ,"%b _%d %H:%M:%S"},
        {TimeStampFormat::Kitchen    ,"%I:%M%p"},                               // Not Working
        {TimeStampFormat::NONE       ,""},
    };

    const char *start = *it;
    while (**it != endToken) { (*it)++; }
    std::string sw { start, (size_t)((*it) - start) };
    std::istringstream ss;

    TimeStampFormat i;
    for(i = TimeStampFormat::Layout; i != TimeStampFormat::NONE; i = static_cast<TimeStampFormat>(static_cast<int>(i) + 1)) {
        ss.clear(); //may this be costly to the performance?
        ss.str(sw);
        // ss.imbue(std::locale("en_US.UTF-8")); // check in which cases this could be nnecesary
        ss >> parse(TimeStampFormatMapper.at(i), tp);
        if(!ss.fail()) {
            auto tp_days = floor<days>(tp);
            auto ymd = year_month_day{tp_days};
            auto time = make_time(std::chrono::duration_cast<std::chrono::milliseconds>(tp - tp_days));

            tsr.year = std::to_string(int(ymd.year()));
            tsr.month = std::to_string(uint(ymd.month()));
            tsr.day = std::to_string(uint(ymd.day()));
            tsr.hour = std::to_string(int(time.hours().count()));
            tsr.minutes = std::to_string(int(time.minutes().count()));
            tsr.seconds = std::to_string(int(time.seconds().count())) + "." + std::to_string((time.subseconds().count()));
            return true;
        }
    }

    if(i == TimeStampFormat::NONE){
        return false;
    }
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
