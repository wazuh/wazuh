#include "SpecificParsers.hpp"

#include <chrono>
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
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "tld.hpp"

// TODO For all the rfc timestamps there are variations that we don't parse
// still, this will need a rework on how this list work
static const std::unordered_map<std::string, const char *>
    kTimeStampFormatMapper = {
        { "ANSIC", "%a %b %d %T %Y" },
        { "APACHE", "%a %b %d %T %Y" }, // need to find the apache ts format
        { "Kitchen", "%I:%M%p" },       // Not Working
        { "RFC1123", "%a, %d %b %Y %T %Z" },
        { "RFC1123Z", "%a, %d %b %Y %T %z" },
        { "RFC3339", "%FT%TZ%Ez" },
        { "RFC822", "%d %b %y %R %Z" },
        { "RFC822Z", "%d %b %y %R %z" },
        { "RFC850", "%A, %d-%b-%y %T %Z" },
        { "RubyDate", "%a %b %d %H:%M:%S %z %Y" },
        { "Stamp", "%b %d %T" },
        { "UnixDate", "%a %b %d %T %Z %Y" },
    };

std::string parseAny(const char **it, char endToken) {
    const char *start = *it;
    while (**it != endToken && **it != '\0') { (*it)++; }
    return { start, *it };
}

bool matchLiteral(const char **it, std::string const& literal) {
    size_t i = 0;
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

void parseFilePath(const char **it, char endToken, std::vector<std::string> const& captureOpts, FilePathResult &result) {
    const char *start = *it;
    while (**it != endToken && **it != '\0') { (*it)++; }
    std::string_view file_path { start, (size_t)((*it) - start) };
    std::string folder_separator = "/\\";
    bool search_drive_letter = true;
    if (!captureOpts.empty() && captureOpts[0] == "UNIX") {
        search_drive_letter = false;
        folder_separator = "/";
    }

    result.path = file_path;
    auto folder_end = file_path.find_last_of(folder_separator);
    result.folder = folder_end == std::string::npos ? "" : file_path.substr(0, folder_end);
    result.name = folder_end == std::string::npos ? file_path : file_path.substr(folder_end + 1);
    auto extension_start = result.name.find_last_of('.');
    result.extension = extension_start == std::string::npos ? "" : result.name.substr(extension_start + 1);
    if (search_drive_letter && file_path[1] == ':' && (file_path[2] == '\\' || file_path[2] == '/')) {
        result.drive_letter = std::toupper(file_path[0]);
    }
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

static bool parseFormattedTime(const char *fmt,
                               std::string const &time,
                               TimeStampResult &ret)
{
    std::stringstream ss { time };
    // check in which cases this could be necessary
    // ss.imbue(std::locale("en_US.UTF-8"));
    date::fields<std::chrono::nanoseconds> fds {};
    std::chrono::minutes offset {};
    std::string abbrev;
    date::from_stream(ss, fmt, fds, &abbrev, &offset);
    if (!ss.fail())
    {
        if (fds.ymd.year().ok())
        {
            ret.year = std::to_string(static_cast<int>(fds.ymd.year()));
        }

        if (fds.ymd.month().ok())
        {
            ret.month = std::to_string(static_cast<unsigned>(fds.ymd.month()));
        }

        if (fds.ymd.day().ok())
        {
            ret.day = std::to_string(static_cast<unsigned>(fds.ymd.day()));
        }

        if (fds.has_tod && fds.tod.in_conventional_range())
        {
            ret.hour    = std::to_string(fds.tod.hours().count());
            ret.minutes = std::to_string(fds.tod.minutes().count());
            ret.seconds = std::to_string(fds.tod.seconds().count());
            auto subsec = fds.tod.subseconds().count();
            if (subsec > 0)
            {
                // TODO check if this is necessary
                // Remove the 'extra' 0 at the end
                while ((subsec % 10) == 0)
                {
                    subsec /= 10;
                }
                ret.seconds += "." + std::to_string(subsec);
            }

            if (offset.count() != 0)
            {
                date::hh_mm_ss<std::chrono::minutes> t { offset };
                char str[6] = { 0 };
                snprintf(str,
                         6,
                         t.is_negative() ? "-%02lu%02lu" : "%02lu%02lu",
                         t.hours().count(),
                         t.minutes().count());
                ret.timezone = str;
            }
            else if (!abbrev.empty())
            {
                ret.timezone = std::move(abbrev);
            }
        }
        return true;
    }
    return false;
}

bool parseTimeStamp(const char **it,
                    std::vector<std::string> const &opts,
                    char endToken,
                    TimeStampResult &tsr)
{
    const char *start = *it;
    while (**it != endToken && **it != '\0') { (*it)++; }
    std::string tsStr { start, (size_t)((*it) - start) };

    if (!opts.empty())
    {
        bool ret = false;
        auto it  = kTimeStampFormatMapper.find(opts[0]);
        if (it != kTimeStampFormatMapper.end())
        {
            ret = parseFormattedTime(it->second, tsStr, tsr);
        }
        else
        {
            // TODO report error
        }
        return ret;
    }
    else
    {
        for (auto const &fmt : kTimeStampFormatMapper)
        {
            if (parseFormattedTime(fmt.second, tsStr, tsr))
            {
                return true;
            }
        }
    }

    // TODO report error
    return false;
}

bool parseURL(const char **it, char endToken, URLResult &result) {
    const char *start = *it;
    // TODO Check how to handle if the URL contains the endToken
    while (**it != endToken && **it != '\0') { (*it)++; }

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

static bool isAsciiNum(char c){ return (c <= '9' && c >= '0');}
static bool isAsciiUpp(char c){ return (c <= 'Z' && c >= 'A');}
static bool isAsciiLow(char c){ return (c <= 'z' && c >= 'a');}
static bool isDomainValidChar(char c) {
    return ( isAsciiNum(c) || isAsciiUpp(c) || isAsciiLow(c) || c == '-' || c == '_' || c == '.' );
}

bool parseDomain(const char **it, char endToken, std::vector<std::string> const& captureOpts, DomainResult &result) {
    constexpr int DOMAIN_MAX_SIZE = 253;
    constexpr int LABEL_MAX_SIZE = 63;
    const bool validate_FQDN = (!captureOpts.empty() && captureOpts[0] == "FQDN");

    const char *start = *it;
    while (**it != endToken && **it != '\0') { (*it)++; }
    std::string_view str { start, (size_t)((*it) - start) };

    size_t protocol_end = str.find("://");
    size_t domain_start = 0;
    // Protocol
    if (std::string::npos != protocol_end) {
        result.protocol = str.substr(0, protocol_end);
        domain_start = protocol_end + 3;
    }
    size_t domain_end = str.find("/", protocol_end + 3);
    // Domain
    result.domain = str.substr(domain_start, domain_end - domain_start);
    // Domain length check
    if (result.domain.empty() || result.domain.length() > DOMAIN_MAX_SIZE){
        //TODO Log domain size error
        return false;
    }
    // Domain valid characters check
    for (char const &c: result.domain) {
        if (!isDomainValidChar(c)) {
            //TODO Log invalid char error
            return false;
        }
    }
    // Route
    if (std::string::npos != domain_end) {
        result.route = str.substr(domain_end+1);
    }

    // TODO We can avoid the string duplication by using string_view. This will require to change the logic to avoid deleting the used labels.
    std::vector<std::string> labels;
    size_t start_label = 0;
    size_t end_label = 0;
    while (end_label != std::string::npos) {
        end_label = result.domain.find('.', start_label);
        // TODO: Avoid String duplication here.
        labels.emplace_back(result.domain.substr(start_label, end_label - start_label));
        if (labels.back().empty() || labels.back().length() > LABEL_MAX_SIZE) {
            //TODO Log label size error
            return false;
        }
        start_label = end_label + 1;
    }

    // Guess the TLD
    if (ccTLDlist.find(labels.back()) != ccTLDlist.end()) {
        result.top_level_domain = labels.back();
        labels.pop_back();
    }
    if (popularTLDlist.find(labels.back()) != popularTLDlist.end()) {
        if (result.top_level_domain.empty()) {
            result.top_level_domain = labels.back();
        }
        else {
            result.top_level_domain = labels.back() + "." + result.top_level_domain;
        }
        labels.pop_back();
    }

    // Registered domain
    if (result.top_level_domain.empty()) {
        result.registered_domain = labels.back();
    }
    else {
        result.registered_domain = labels.back() + "." + result.top_level_domain;
    }
    labels.pop_back();

    // Subdomain
    for (auto label : labels) {
        if (result.subdomain.empty()) {
            result.subdomain = label;
        }
        else {
            result.subdomain = result.subdomain + "." + label;
        }
    }

    // Address
    result.address = result.domain;

    // Validate if all fields are complete to identify a Fully Qualified Domain Name
    if (validate_FQDN) {
        if (result.top_level_domain.empty()) {
            //TODO log error
            return false;
        }
        if (result.registered_domain.empty()) {
            //TODO log error. One for each missing field?
            return false;
        }
        if (result.subdomain.empty()) {
            //TODO log error. One for each missing field?
            return false;
        }
    }

    return true;
}
