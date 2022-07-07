#include <climits>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#include "date/date.h"
#include "hlpDetails.hpp"
#include "specificParsers.hpp"
#include "tld.hpp"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <fmt/format.h>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#include <profile/profile.hpp>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

// TODO For all the rfc timestamps there are variations that we don't parse
// still, this will need a rework on how this list work
static const std::unordered_map<std::string_view, std::tuple<const char*, const char*>>
    kTimeStampFormatMapper = {
        // {"ANSIC", "%a %b %d %T %Y"},
        // {"APACHE", "%a %b %d %T %Y"}, // need to find the apache ts format
        // {"Kitchen", "%I:%M%p"},       // Not Working
        // {"RFC1123", "%a, %d %b %Y %T %Z"},
        // {"RFC1123Z", "%a, %d %b %Y %T %z"},
        // {"RFC3339", "%FT%TZ%Ez"},
        // {"RFC822", "%d %b %y %R %Z"},
        // {"RFC822Z", "%d %b %y %R %z"},
        // {"RFC850", "%A, %d-%b-%y %T %Z"},
        // {"RubyDate", "%a %b %d %H:%M:%S %z %Y"},
        // {"Stamp", "%b %d %T"},
        // {"UnixDate", "%a %b %d %T %Z %Y"},
        {"SYSLOG", {"%b %d %T", "Jun 14 15:16:01"}},
        {"ISO8601", {"%Y-%d-%mT%T%z", "2018-08-14T14:30:02.203151+02:00"}},
        {"HTTPDATE", {"%d/%b/%Y:%T %z", "26/Dec/2016:16:22:14 +0000"}},
        {"NGINX_ERROR", {"%Y/%m/%d %T", "2016/10/25 14:49:34"}},
        {"APACHE_ERROR", {"%a %b %d %T %Y", "Mon Dec 26 16:15:55.103786 2016"}},
        {"APACHE_ERROR2", {"%a %b %d %T %Y", "Mon Dec 26 16:15:55 2016"}},
};

bool configureTsParser(Parser& parser, std::vector<std::string_view> const& args)
{
    auto it = kTimeStampFormatMapper.find(args[0]);
    if (it != kTimeStampFormatMapper.end())
    {
        parser.options.push_back(it->first.data());
        return true;
    }
    else
    {
        throw std::runtime_error(fmt::format(
            "[configureTsParser(parser, args)] Unknown timestamp format: {}", args[0]));
    }
}

bool configureMapParser(Parser& parser, std::vector<std::string_view> const& args)
{
    size_t argsSize = args.size();
    if (argsSize < 2 || argsSize > 3)
    {
        auto msg = fmt::format(
            "[HLP] Invalid arguments for map Parser. Expected 2 or 3, got [{}]",
            argsSize);
        throw std::runtime_error(msg);
    }

    char opt[4] = {0};
    opt[0] = args[0][0];
    opt[1] = args[1][0];
    opt[2] = (argsSize == 3) ? args[2][0] : parser.endToken;
    parser.options.push_back(opt);

    return true;
}

bool configureFilepathParser(Parser& parser, std::vector<std::string_view> const& args)
{
    std::string folderSeparator = "/\\";
    bool hasDriveLetter = true;
    if (!args.empty() && args[0] == "UNIX")
    {
        hasDriveLetter = false;
        folderSeparator = "/";
    }

    parser.options.push_back(folderSeparator);
    if (hasDriveLetter)
    {
        // TODO this is a hack to demonstrate the pattern
        parser.options.push_back({});
    }

    return true;
}

bool configureDomainParser(Parser& parser, std::vector<std::string_view> const& args)
{
    if (!args.empty() && args[0] == "FQDN")
    {
        // TODO this is a hack to demonstrate the pattern
        parser.options.push_back({});
    }

    return true;
}

bool configureAnyParser(Parser& parser, std::vector<std::string_view> const& args)
{
    parser.endToken = '\0';
    return true;
}

bool configureQuotedString(Parser& parser, std::vector<std::string_view> const& args)
{
    if (args.empty())
    {
        parser.options.push_back("\"");
        parser.options.push_back("\"");
    }
    else if (args.size() == 1)
    {
        parser.options.push_back(std::string {args[0]});
        parser.options.push_back(std::string {args[0]});
    }
    else if (args.size() == 2)
    {
        parser.options.push_back(std::string {args[0]});
        parser.options.push_back(std::string {args[1]});
    }
    else
    {
        auto msg = fmt::format("[HLP] Invalid arguments for quoted string Parser. "
                               "Expected 0, 1 or 2, got [{}]",
                               args.size());
        throw std::runtime_error(msg);
    }

    return true;
}

bool configureBooleanParser(Parser& parser, std::vector<std::string_view> const& args)
{
    if (!args.empty())
    {
        parser.options.emplace_back(args[0]);
    }
    else
    {
        parser.options.emplace_back("true");
    }

    return true;
}

bool configureIgnoreParser(Parser& parser, std::vector<std::string_view> const& args)
{
    if (!args.empty())
    {
        if (args.size() == 1)
        {
            parser.options.push_back(std::string {args[0]});
        }
        else
        {
            auto msg = fmt::format("[HLP] Invalid arguments for ignore Parser. "
                                   "Expected 0 or 1, got [{}]",
                                   args.size());
            throw std::runtime_error(msg);
        }
    }
    return true;
}

bool parseIgnore(const char** it, Parser const& parser, ParseResult& result)
{
    auto start = *it;
    if (!parser.options.empty())
    {
        auto ignoreStr = parser.options[0];
        size_t ignoreLen = ignoreStr.size();
        bool ignore = true;

        auto checkIgnore = [&](const char** it)
        {
            auto start = **it;
            for (auto i = 0; **it != '\0' && i < ignoreLen; ++i, ++*it)
            {
                if (**it != ignoreStr[i])
                {
                    (*it) -= i;
                    return false;
                }
            }
            return true;
        };

        while (**it != '\0')
        {
            if (!checkIgnore(it))
            {
                break;
            }
        }
    }
    else
    {
        while (**it != '\0')
        {
            if (**it == parser.endToken)
            {
                break;
            }
            ++*it;
        }
    }

    result[parser.name] = std::string {start, *it};
    return true;
}

bool parseAny(const char** it, Parser const& parser, ParseResult& result)
{
    const char* start = *it;
    while (**it != '\0' && **it != parser.endToken)
    {
        (*it)++;
    }
    // TODO check if we can get away with a string_view
    result[parser.name] = std::string {start, *it};
    return true;
}

bool matchLiteral(const char** it, Parser const& parser, ParseResult&)
{
    size_t i = 0;
    for (; (**it) && (i < parser.name.size());)
    {
        // Skip over the escaping '\'
        if (**it == '\\')
        {
            continue;
        }

        if (**it != parser.name[i])
        {
            return false;
        }

        (*it)++;
        i++;
    }

    return parser.name[i] == '\0';
}

bool parseFilePath(const char** it, Parser const& parser, ParseResult& result)
{
    const char* start = *it;
    while (**it != parser.endToken && **it != '\0')
    {
        (*it)++;
    }

    std::string_view filePath {start, (size_t) ((*it) - start)};
    auto& folderSeparator = parser.options[0];
    // TODO hack
    bool hasDriveLetter = (parser.options.size() == 2);

    auto path = filePath;
    auto folderEnd = filePath.find_last_of(folderSeparator);

    auto folder = (folderEnd == std::string::npos) ? "" : filePath.substr(0, folderEnd);

    auto name =
        (folderEnd == std::string::npos) ? filePath : filePath.substr(folderEnd + 1);

    auto extensionStart = name.find_last_of('.');
    auto extension =
        (extensionStart == std::string::npos) ? "" : name.substr(extensionStart + 1);

    std::string driveLetter;
    if (hasDriveLetter && filePath[1] == ':'
        && (filePath[2] == '\\' || filePath[2] == '/'))
    {
        driveLetter = std::toupper(filePath[0]);
    }

    result[parser.name + ".path"] = std::string {filePath};
    result[parser.name + ".drive_letter"] = std::string {driveLetter};
    result[parser.name + ".folder"] = std::string {folder};
    result[parser.name + ".name"] = std::string {name};
    result[parser.name + ".extension"] = std::string {extension};

    return true;
}

bool parseJson(const char** it, Parser const& parser, ParseResult& result)
{
    rapidjson::Reader reader;
    rapidjson::StringStream ss {*it};
    auto h = rapidjson::BaseReaderHandler {};
    if (reader.Parse<rapidjson::kParseStopWhenDoneFlag>(ss, h).IsError())
    {
        return false;
    }

    hlp::JsonString json {{*it, ss.Tell()}};
    *it += ss.Tell();

    result[parser.name] = json;

    return true;
}

bool parseMap(const char** it, Parser const& parser, ParseResult& result)
{
    WAZUH_TRACE_FUNCTION;
    char pairSeparator = parser.options[0][0];
    char kvSeparator = parser.options[0][1];
    char endMapToken = parser.options[0][2];

    const char* start = *it;
    while (**it != '\0' && **it != endMapToken)
    {
        (*it)++;
    }

    std::string_view map_str {start, static_cast<size_t>((*it) - start)};
    *it += (endMapToken
            != parser.endToken); // Theres probably the special case where they where
                                 // the same but the endMapToken was specified

    rapidjson::Document output_doc;
    output_doc.SetObject();
    auto& allocator = output_doc.GetAllocator();

    size_t tuple_start_pos = 0;
    bool done = false;
    while (!done)
    {
        size_t separator_pos = map_str.find(kvSeparator, tuple_start_pos);
        if (separator_pos == std::string::npos)
        {
            // TODO Log error: Missing Separator
            break;
        }
        size_t tuple_end_pos = map_str.find(pairSeparator, separator_pos);
        std::string key_str(
            map_str.substr(tuple_start_pos, separator_pos - tuple_start_pos));
        std::string value_str(
            map_str.substr(separator_pos + 1, tuple_end_pos - (separator_pos + 1)));

        if (key_str.empty() || value_str.empty())
        {
            // TODO Log error: Empty map fields
            break;
        }
        else if (tuple_end_pos == std::string::npos)
        {
            // Map ended
            done = true;
        }
        tuple_start_pos = tuple_end_pos + 1;

        output_doc.AddMember(rapidjson::Value(key_str.c_str(), allocator),
                             rapidjson::Value(value_str.c_str(), allocator),
                             allocator);
    }

    if (!done)
    {
        // TODO report error
        return false;
    }

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    output_doc.Accept(writer);

    result[parser.name] = hlp::JsonString {s.GetString()};

    return true;
}

bool parseIPaddress(const char** it, Parser const& parser, ParseResult& result)
{
    struct in_addr ip;
    struct in6_addr ipv6;
    const char* start = *it;
    while (**it != 0 && **it != parser.endToken)
    {
        (*it)++;
    }

    std::string srcip {start, (size_t) ((*it) - start)};
    if (inet_pton(AF_INET, srcip.c_str(), &ip))
    {
        // TODO check if we can get away with a string_view
        result[parser.name] = std::string {start, *it};
        return true;
    }
    else if (inet_pton(AF_INET6, srcip.c_str(), &ipv6))
    {
        // TODO check if we can get away with a string_view
        result[parser.name] = std::string {start, *it};
        return true;
    }

    // TODO report error
    return false;
}

static bool parseFormattedTime(std::string const& fmt,
                               std::string const& time,
                               ParseResult& result,
                               std::string const& name)
{
    std::stringstream ss {time};
    // check in which cases this could be necessary
    // ss.imbue(std::locale("en_US.UTF-8"));
    date::fields<std::chrono::nanoseconds> fds {};
    std::chrono::minutes offset {};
    std::string abbrev;
    date::from_stream(ss, fmt.c_str(), fds, &abbrev, &offset);
    if (!ss.fail())
    {
        result[name] = ss.str();
        // std::cout << "FormattedTime string: " << ss.str() << std::endl;
        // std::cout << "FormattedTime offset: " << offset.count() << std::endl;
        // std::cout << "FormattedTime abbrev: " << abbrev << std::endl;

        // if (fds.ymd.year().ok())
        // {
        //     result[name + ".year"] = static_cast<int>(fds.ymd.year());
        // }

        // if (fds.ymd.month().ok())
        // {
        //     result[name + ".month"] = static_cast<unsigned>(fds.ymd.month());
        // }

        // if (fds.ymd.day().ok())
        // {
        //     result[name + ".day"] = static_cast<unsigned>(fds.ymd.day());
        // }

        // if (fds.has_tod && fds.tod.in_conventional_range())
        // {
        //     result[name + ".hour"] = fds.tod.hours().count();
        //     result[name + ".minutes"] = fds.tod.minutes().count();

        //     // result[name + ".seconds"] =
        //     // std::to_string(fds.tod.seconds().count());
        //     auto secs = fds.tod.seconds() + fds.tod.subseconds();

        //     result[name + ".seconds"] = static_cast<double>(secs.count() / 1e9);

        //     if (offset.count() != 0)
        //     {
        //         date::hh_mm_ss<std::chrono::minutes> t {offset};
        //         char str[6] = {0};
        //         snprintf(str,
        //                  6,
        //                  t.is_negative() ? "-%02lu%02lu" : "%02lu%02lu",
        //                  t.hours().count(),
        //                  t.minutes().count());
        //         result[name + ".timezone"] = std::string {str};
        //     }
        //     else if (!abbrev.empty())
        //     {
        //         result[name + ".timezone"] = abbrev;
        //     }
        // }
        return true;
    }

    return false;
}

bool parseTimeStamp(const char** it, Parser const& parser, ParseResult& result)
{
    if (!parser.options.empty())
    {
        // TODO: move to configureTsParser
        auto tsName = parser.options[0];

        std::string tsExample = std::get<1>(kTimeStampFormatMapper.at(tsName));
        auto tsSize = tsExample.size();

        auto tsFormat = std::get<0>(kTimeStampFormatMapper.at(tsName));

        const char* start = *it;
        for (auto i = 0; i < tsSize; i++, (*it)++)
        {
            if (**it == '\0')
            {
                return false;
            }
        }

        std::string tsStr {start, tsSize};

        // TODO assert options?
        return parseFormattedTime(tsFormat, tsStr, result, parser.name);
    }
    else
    {
        // for (auto const &fmt : kTimeStampFormatMapper)
        // {
        //     if (parseFormattedTime(fmt.second, tsStr, result, parser.name))
        //     {
        //         return true;
        //     }
        // }
        return false;
    }

    // TODO report error
    return false;
}

bool parseURL(const char** it, Parser const& parser, ParseResult& result)
{
    // TODO should we fill partial results?

    const char* start = *it;
    // TODO Check how to handle if the URL contains the endToken
    while (**it != parser.endToken && **it != '\0')
    {
        (*it)++;
    }

    auto urlCleanup = [](auto* url)
    {
        curl_url_cleanup(url);
    };

    std::unique_ptr<CURLU, decltype(urlCleanup)> url {curl_url(), urlCleanup};

    if (url == nullptr)
    {
        // TODO error
        return false;
    }

    std::string urlStr {start, *it};
    auto uc = curl_url_set(url.get(), CURLUPART_URL, urlStr.c_str(), 0);
    if (uc)
    {
        // TODO error handling
        return false;
    }

    // TODO curl will parse and copy the URL into an allocated
    // char ptr and we will copy it again into the string for the result
    // Check if there's a way to avoid all the copying here
    char* str;
    uc = curl_url_get(url.get(), CURLUPART_URL, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".original"] = std::string {str};
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_HOST, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".domain"] = std::string {str};
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_PATH, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".path"] = std::string {str};
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_SCHEME, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".scheme"] = std::string {str};
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_USER, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".username"] = std::string {str};
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_PASSWORD, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".password"] = std::string {str};
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_QUERY, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".query"] = std::string {str};
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_PORT, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".port"] = std::atoi(str);
    curl_free(str);

    uc = curl_url_get(url.get(), CURLUPART_FRAGMENT, &str, 0);
    if (uc)
    {
        // TODO set an error someway
        return false;
    }
    result[parser.name + ".fragment"] = std::string {str};
    curl_free(str);

    return true;
}

static bool isAsciiNum(char c)
{
    return (c <= '9' && c >= '0');
}
static bool isAsciiUpp(char c)
{
    return (c <= 'Z' && c >= 'A');
}
static bool isAsciiLow(char c)
{
    return (c <= 'z' && c >= 'a');
}
static bool isDomainValidChar(char c)
{
    return (isAsciiNum(c) || isAsciiUpp(c) || isAsciiLow(c) || c == '-' || c == '_'
            || c == '.');
}

bool parseDomain(const char** it, Parser const& parser, ParseResult& result)
{

    constexpr int kDomainMaxSize = 253;
    constexpr int kLabelMaxSize = 63;

    // TODO hack
    const bool validateFQDN = !parser.options.empty();

    const char* start = *it;
    while (**it != parser.endToken && **it != '\0')
    {
        (*it)++;
    }
    std::string_view str {start, (size_t) ((*it) - start)};

    size_t protocolEnd = str.find("://");
    size_t domainStart = 0;
    // Protocol
    std::string protocol;
    if (std::string::npos != protocolEnd)
    {
        protocol = str.substr(0, protocolEnd);
        domainStart = protocolEnd + 3;
    }
    size_t domainEnd = str.find("/", protocolEnd + 3);
    // Domain
    auto domain = str.substr(domainStart, domainEnd - domainStart);
    // Domain length check
    if (domain.empty() || domain.length() > kDomainMaxSize)
    {
        // TODO Log domain size error
        return false;
    }
    // Domain valid characters check
    for (char const& c : domain)
    {
        if (!isDomainValidChar(c))
        {
            // TODO Log invalid char error
            return false;
        }
    }
    // Route
    std::string route;
    if (std::string::npos != domainEnd)
    {
        route = str.substr(domainEnd + 1);
    }

    // TODO We can avoid the string duplication by using string_view. This will
    // require to change the logic to avoid deleting the used labels.
    std::vector<std::string> labels;
    size_t startLabel = 0;
    size_t endLabel = 0;
    while (endLabel != std::string::npos)
    {
        endLabel = domain.find('.', startLabel);
        // TODO: Avoid String duplication here.
        labels.emplace_back(domain.substr(startLabel, endLabel - startLabel));
        if (labels.back().empty() || labels.back().length() > kLabelMaxSize)
        {
            // TODO Log label size error
            return false;
        }
        startLabel = endLabel + 1;
    }

    // Guess the TLD
    std::string topLevelDomain;
    if (ccTLDlist.find(labels.back()) != ccTLDlist.end())
    {
        topLevelDomain = labels.back();
        labels.pop_back();
    }
    if (popularTLDlist.find(labels.back()) != popularTLDlist.end())
    {
        if (topLevelDomain.empty())
        {
            topLevelDomain = labels.back();
        }
        else
        {
            topLevelDomain = labels.back() + "." + topLevelDomain;
        }
        labels.pop_back();
    }

    // Registered domain
    std::string registeredDomain;
    if (topLevelDomain.empty())
    {
        registeredDomain = labels.back();
    }
    else
    {
        registeredDomain = labels.back() + "." + topLevelDomain;
    }
    labels.pop_back();

    // Subdomain
    std::string subdomain;
    for (auto label : labels)
    {
        if (subdomain.empty())
        {
            subdomain = label;
        }
        else
        {
            subdomain = subdomain + "." + label;
        }
    }

    // Address
    auto address = domain;

    // Validate if all fields are complete to identify a Fully Qualified Domain
    // Name
    if (validateFQDN)
    {
        if (topLevelDomain.empty())
        {
            // TODO log error
            return false;
        }
        if (registeredDomain.empty())
        {
            // TODO log error. One for each missing field?
            return false;
        }
        if (subdomain.empty())
        {
            // TODO log error. One for each missing field?
            return false;
        }
    }

    result[parser.name + ".domain"] = std::move(domain);
    result[parser.name + ".subdomain"] = std::move(subdomain);
    result[parser.name + ".registered_domain"] = std::move(registeredDomain);
    result[parser.name + ".top_level_domain"] = std::move(topLevelDomain);
    result[parser.name + ".address"] = std::move(address);

    return true;
}

enum class UAState
{
    Product,
    Comment,
};

bool parseUserAgent(const char** it, Parser const& parser, ParseResult& result)
{
    const char* start = *it;
    const char* ev = *it;

    // NOTE: This will try to validate 'some' part of the user-agent standard as
    // is defined in https://datatracker.ietf.org/doc/html/rfc7231#section-5.5.3
    // It will accept as valid only User agents with the form of - token/token
    // (comment) token/token - or - token/token token/token - Other ~valid~
    // formats of User agents like:
    //     - Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like
    //     Gecko
    //     - product1/version1 product2/version2 product3
    //     - product/version (comment, (nested comment))
    // are not considered valid because it would be impossible to differentiate
    // from a 'literal'

    bool done = false;
    UAState state = UAState::Product;
    const char* lastValid = ev;
    while (!done)
    {
        switch (state)
        {
            case UAState::Product:
            {
                bool valid = false;
                // TODO this easily breaks if the user agent has an end
                // token in it
                while (ev[0] && ev[0] != ' ' && ev[0] != parser.endToken)
                {
                    if (ev[0] == '/')
                    {
                        valid = true;
                    }
                    ev++;
                }

                if (!valid)
                {
                    done = true;
                    continue;
                }

                ev += (ev[0] == ' ');
                lastValid = ev;
                state = UAState::Comment;
                break;
            }
            case UAState::Comment:
            {
                if (ev[0] == '(')
                {
                    // TODO this easily breaks if the user agent has an end
                    // token in it
                    while (ev[0] && ev[0] != ')' && ev[0] != parser.endToken)
                    {
                        ev++;
                    }

                    if (ev[0] && ev[1] == ' ')
                    {
                        lastValid = ev;
                        ev += 2;
                        state = UAState::Product;
                    }
                    else
                    {
                        // TODO is this an error???
                        done = true;
                        continue;
                    }
                }
                else
                {
                    // We got 0 comments or an invalid string
                    state = UAState::Product;
                }
                break;
            }
        }
    }

    // TODO check type and see if we can get away with a string_view
    result[parser.name + ".original"] = std::string {start, lastValid};

    *it = lastValid;
    return true;
}

bool parseNumber(const char** it, Parser const& parser, ParseResult& result)
{
    const char* start = *it;
    char* ptrEnd;
    bool hasDecimalSeparator = false;
    float fnum;
    long int val;

    if (**it == '+' || **it == '-')
    {
        (*it)++;
    }

    while (**it != '\0' && **it != parser.endToken)
    {
        if (!hasDecimalSeparator && **it == '.')
        {
            hasDecimalSeparator = true;
        }
        else if (!std::isdigit(**it))
        {
            return false;
        }
        (*it)++;
    }

    if (!hasDecimalSeparator)
    {
        val = std::strtol(start, &ptrEnd, 10);
        // TODO: if the number is exactly any of the limits it will fail
        if (start == ptrEnd || val == LLONG_MAX || val == LLONG_MIN)
        {
            return false;
        }
        result[parser.name] = val;
    }
    else
    {
        // TODO: if the number surpass limits won't fail
        fnum = std::strtof(start, &ptrEnd);
        if (start == ptrEnd)
        {
            return false;
        }
        result[parser.name] = fnum;
    }

    return true;
}

bool parseQuotedString(const char** it, Parser const& parser, ParseResult& result)
{
    bool escaped = false;

    const auto& startQuote = parser.options[0];
    const auto& endQuote = parser.options[1];

    for (const auto& ch : startQuote)
    {
        if (**it != ch)
        {
            return false;
        }
        (*it)++;
    }

    const char* start = *it;

    auto checkEnd = [&](const char** it)
    {
        for (const auto& ch : endQuote)
        {
            if (**it != ch)
            {
                return false;
            }
            (*it)++;
        }
        return true;
    };
    auto foundEnd = false;

    while (**it != '\0' && (escaped || !foundEnd))
    {
        escaped = **it == '\\';
        foundEnd = checkEnd(it);
        if (!foundEnd)
        {
            (*it)++;
        }
    }

    if (!foundEnd)
    {
        return false;
    }

    const char* end = *it - endQuote.size() - 1;
    result[parser.name] = std::string {start, end};
    return true;
}

bool parseBoolean(const char** it, Parser const& parser, ParseResult& result)
{
    const char* start = *it;
    while (**it != parser.endToken && **it != '\0')
    {
        (*it)++;
    }
    std::string_view str {start, (size_t) ((*it) - start)};

    auto& trueVal = parser.options[0];
    result[parser.name] = bool {str == trueVal};
    return true;
}
