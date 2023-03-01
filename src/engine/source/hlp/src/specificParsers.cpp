#include "specificParsers.hpp"

#include <climits>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "date/date.h"
#include "tld.hpp"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <profile/profile.hpp>
#include <pugixml.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <fmt/format.h>
#include <json/json.hpp>

#include "hlpDetails.hpp"

namespace
{
/**
 * @brief Enum for classifying the type of a json value
 */
enum class JSON_TYPE
{
    J_ANY,
    J_STRING,
    J_BOOL,
    J_NUMBER,
    J_OBJECT,
    J_ARRAY,
    J_NULL
};

/**
 * @brief Asociates a JSON_TYPE with a string
 */
static const std::unordered_map<std::string_view, JSON_TYPE> jsonTypes = {
    {"string", JSON_TYPE::J_STRING},
    {"bool", JSON_TYPE::J_BOOL},
    {"number", JSON_TYPE::J_NUMBER},
    {"object", JSON_TYPE::J_OBJECT},
    {"array", JSON_TYPE::J_ARRAY},
    {"null", JSON_TYPE::J_NULL},
    {"any", JSON_TYPE::J_ANY}};

/**
 * @brief check if a string is a valid json type
 *
 * @param type the string to check
 * @return true if the string is a valid json type, false otherwise.
 */
bool validJsonType(std::string_view type)
{
    return jsonTypes.find(type) != jsonTypes.end();
}

/**
 * @brief Convert and insert a json value into a json object
 *
 * @param outputDoc the json object to insert the value into
 * @param key the key to insert the value into
 * @param value the value to insert
 */
void addValueToJson(rapidjson::Document& outputDoc,
                    std::string_view key,
                    std::string_view value)
{
    auto& allocator = outputDoc.GetAllocator();
    // Check the value type and cast it
    auto jsonValue {rapidjson::Value(rapidjson::kNullType)};
    if (!value.empty())
    {

        // Check if the value maybe is a negative number
        bool negativeNumber = (('-' == value[0]) && (value.size() > 1));

        if (value.find_first_not_of("0123456789.", negativeNumber ? 1 : 0)
            == std::string_view::npos)
        {
            // Number
            if (value.find('.') != std::string_view::npos)
            {
                jsonValue.SetDouble(std::stod(std::string(value)));
            }
            else
            {
                jsonValue.SetInt64(std::stoll(std::string(value)));
            }
        }
        else
        {
            // Add string value
            jsonValue = rapidjson::Value(std::string(value).c_str(), allocator);
        }
    }
    // TODO Check if every argument is a valid json key
    outputDoc.AddMember(rapidjson::Value(std::string(key).c_str(), allocator),
                         jsonValue.Move(),
                         allocator);
}

} // namespace

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
        {"RFC3154_ID_TIMEZONE", {"%b %d %R:%6S %Z", "Mar  1 18:48:50.483 UTC"}},
        {"RFC3154_TIMEZONE", {"%b %d %T %Z", "Mar  1 18:48:50 UTC"}},
        {"24H_LOCALTIME", {"%T", "15:16:01"}},
        {"SYSLOG", {"%b %d %T", "Jun 14 15:16:01"}}, // TODO specify the RCF, rfc3164?
        {"ISO8601", {"%Y-%m-%dT%T%z", "2018-08-14T14:30:02.203151+02:00"}},
        {"ISO8601_Z", {"%Y-%m-%dT%TZ", "2018-08-14T14:30:02.203151Z"}},
        {"HTTPDATE", {"%d/%b/%Y:%T %z", "26/Dec/2016:16:22:14 +0000"}},
        {"NGINX_ERROR", {"%Y/%m/%d %T", "2016/10/25 14:49:34"}},
        {"APACHE_ERROR", {"%a %b %d %T %Y", "Mon Dec 26 16:15:55.103786 2016"}},
        {"APACHE_ERROR2", {"%a %b %d %T %Y", "Mon Dec 26 16:15:55 2016"}},
        {"POSTGRES", {"%Y-%m-%d %T %Z", "2021-02-14 10:45:33 UTC"}},
        {"POSTGRES_MS", {"%Y-%m-%d %T %Z", "2021-02-14 10:45:33.XXX UTC"}},
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
            "Engine HLP specific parsers: Unknown timestamp format of \"{}\".", args[0]));
    }
}

bool configureKVMapParser(Parser& parser, std::vector<std::string_view> const& args)
{
    size_t argsSize = args.size();

    if (2 != argsSize || args[0].empty() || args[1].empty())
    {
        throw std::runtime_error(
            fmt::format("Engine HLP specific parsers: Invalid arguments quantity for "
                        "\"map\" parser, Expected 2 arguments but got {}.",
                        argsSize));
    }

    if (args[0] == args[1])
    {
        throw std::runtime_error(fmt::format(
            "Engine HLP specific parsers: Invalid arguments for \"map\" parser. "
            "Key-Value separator \"{}\" cannot be equal to the pairs separator \"{}\".",
            args[0],
            args[1]));
    }

    // Key-Value Separator
    parser.options.push_back(std::string {args[0]});
    // Pair Separator
    parser.options.push_back(std::string {args[1]});

    return true;
}

bool configureFilepathParser(Parser& parser, std::vector<std::string_view> const& args)
{
    std::string folderSeparator = "/\\";
    bool hasDriveLetter = true;
    if (!args.empty() && "UNIX" == args[0])
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
    if (!args.empty() && "FQDN" == args[0])
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
        throw std::runtime_error(
            fmt::format("Engine HLP specific parsers: Invalid arguments for \"quoted "
                        "string\" parser. Expected 2 arguments at most but got {}.",
                        args.size()));
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
            throw std::runtime_error(
                fmt::format("Engine HLP specific parsers: Invalid arguments for "
                            "\"ignore\" parser. Expected 1 argument at most but got {}.",
                            args.size()));
        }
    }
    return true;
}

bool configureJsonParser(Parser& parser, std::vector<std::string_view> const& args)
{
    // If no arguments parse object
    if (args.empty())
    {
        parser.options.push_back("object");
    }
    else
    {
        // If one argument, it must be a valid json type or "any"
        if (args.size() == 1)
        {
            if (validJsonType(args[0]))
            {
                parser.options.push_back(std::string {args[0]});
            }
            else
            {
                throw std::runtime_error(fmt::format(
                    "Engine HLP specific parsers: Invalid arguments for \"json\" parser. "
                    "Expected one argument of one of the following types: string; bool; "
                    "number; object; array; null or any, but got {}.",
                    args[0]));
            }
        }
        else
        {
            // If more than one argument then is an error
            throw std::runtime_error(
                fmt::format("Engine HLP specific parsers: Invalid quantity of arguments "
                            "for \"json\" parser. Expected 1 argument but got {}.",
                            args.size()));
        }
    }
    return true;
}

bool configureCSVParser(Parser& parser, std::vector<std::string_view> const& args)
{
    if (!args.empty())
    {
        // TODO Check if every argument is a valid json path
        parser.options = std::vector<std::string>(args.begin(), args.end());
    }
    else
    {
        throw std::runtime_error(
            fmt::format("Engine HLP specific parsers: Invalid arguments for \"CVS\" "
                        "parser. Expected 1 argument at least but got {}.",
                        args.size()));
    }
    return true;
}

bool parseIgnore(const char** it, Parser const& parser, ParseResult& result)
{
    auto start = *it;
    auto tmpIt = *it;

    auto retval = true;
    if (!parser.options.empty())
    {
        auto ignoreStr = parser.options[0];
        size_t ignoreLen = ignoreStr.size();

        auto checkIgnore = [&](const char** tmpIt)
        {
            auto start = **tmpIt;
            for (auto i = 0; '\0' != **tmpIt && i < ignoreLen; ++i, ++*tmpIt)
            {
                if (**tmpIt != ignoreStr[i])
                {
                    (*tmpIt) -= i;
                    return false;
                }
            }
            return true;
        };

        while ('\0' != *tmpIt)
        {
            if (!checkIgnore(&tmpIt))
            {
                break;
            }
        }

        if ('\0' == parser.endToken && '\0' != *tmpIt)
        {
            retval = false;
        }
    }
    else
    {
        tmpIt = strchrnul(tmpIt, parser.endToken);
        if (parser.endToken != *tmpIt)
        {
            retval = false;
        }
    }

    if (retval)
    {
        *it = tmpIt;
        result[parser.name] = std::string {start, *it};
    }

    return retval;
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
        if (**it != parser.name[i])
        {
            return false;
        }

        (*it)++;
        i++;
    }

    return ('\0' == parser.name[i]);
}

bool parseFilePath(const char** it, Parser const& parser, ParseResult& result)
{
    const char* start = *it;
    while (**it != parser.endToken && **it != '\0')
    {
        (*it)++;
    }

    std::string_view filePath {start, (size_t)((*it) - start)};
    auto& folderSeparator = parser.options[0];
    // TODO hack
    bool hasDriveLetter = (parser.options.size() == 2);

    auto path = filePath;
    auto folderEnd = filePath.find_last_of(folderSeparator);

    auto folder = (std::string::npos == folderEnd) ? "" : filePath.substr(0, folderEnd);

    auto name =
        (std::string::npos == folderEnd) ? filePath : filePath.substr(folderEnd + 1);

    auto extensionStart = name.find_last_of('.');
    auto extension =
        (std::string::npos == extensionStart) ? "" : name.substr(extensionStart + 1);

    char driveLetter;
    if (hasDriveLetter && ':' == filePath[1]
        && ('\\' == filePath[2] || '/' == filePath[2]))
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
    rapidjson::Document doc;

    // Parse the json and stop at the end of the json object, if error return false
    // TODO: see if there is a way to specify the root JSON type
    doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(ss);
    if (doc.HasParseError())
    {
        return false;
    }

    // If no errors assert root is the correct type
    bool valid = false;
    switch (jsonTypes.at(parser.options[0]))
    {
        case JSON_TYPE::J_ANY: valid = true; break;
        case JSON_TYPE::J_STRING: valid = doc.IsString(); break;
        case JSON_TYPE::J_BOOL: valid = doc.IsBool(); break;
        case JSON_TYPE::J_NUMBER: valid = doc.IsNumber(); break;
        case JSON_TYPE::J_OBJECT: valid = doc.IsObject(); break;
        case JSON_TYPE::J_ARRAY: valid = doc.IsArray(); break;
        case JSON_TYPE::J_NULL: valid = doc.IsNull(); break;
    }

    // Extract the json string and update the pointer
    if (valid)
    {
        hlp::JsonString json {{*it, ss.Tell()}};
        result[parser.name] = json;
        *it += ss.Tell();
    }

    return valid;
}

bool parseKVMap(const char** it, Parser const& parser, ParseResult& result)
{
    WAZUH_TRACE_FUNCTION;

    std::string_view kvSeparator = parser.options[0];
    std::string_view pairSeparator = parser.options[1];
    const char scapeChar = '\\';
    const char endMapToken = parser.endToken;

    // Pointer after last found pair, nullptr if not found
    const char* lastFoundOk = *it;

    /* Json Key-value */
    rapidjson::Document outputDoc;
    outputDoc.SetObject();

    /* -----------------------------------------------
                    Helpers lambdas
     ----------------------------------------------- */

    /*
      Return the pointer to the first `quoteChar` not escaped by `scapeChar` and the
      quoted string If there is no end quoteChar, return a nullptr. WARNING: This function
      can access 1 bytes before the start of the `str`
    */
    const auto getQuoted =
        [&scapeChar](const char* c_str) -> std::pair<const char*, std::string_view>
    {
        const char quoteChar = c_str[0];
        const char* ptr = c_str + 1;
        std::pair<const char*, std::string_view> result = {nullptr, ""};

        while (ptr = strchrnul(ptr, quoteChar), '\0' != *ptr)
        {
            // Is not posible that ptr-2 < str
            bool escaped = (*(ptr - 1) == scapeChar);
            escaped = escaped && (*(ptr - 2) != scapeChar);

            if (!escaped)
            {
                result = {ptr, std::string_view(c_str + 1, ptr - c_str - 1)};
                break;
            }
            ptr++;
        }
        return result;
    };

    /*
      Return the pointer to the first `kvSeparator` not escaped by `scapeChar`.
      If there is no kvSeparator, return NULL
    */
    const auto getSeparator = [&kvSeparator, &scapeChar](const char* c_str)
    {
        const char* ptr = c_str;
        while (ptr = strstr(ptr, kvSeparator.data()), nullptr != ptr)
        {
            bool escaped = false;
            // worst cases:
            //    [=\0], [\=\0],[\\=\0],
            if (ptr + 1 >= c_str)
            {
                escaped = (*(ptr - 1) == scapeChar);
                if (escaped && (ptr + 2 >= c_str))
                {
                    escaped = (*(ptr - 2) != scapeChar);
                }
            }
            if (!escaped)
            {
                break;
            }
            ptr++;
        }

        return ptr;
    };

    /*
      Returns a pair with the pointer to the start value (After key value separator)
      and the string_view to the Key.
      Rerturns a nullptr if there is no key value separator
    */
    const auto getKey =
        [&kvSeparator, &pairSeparator, &scapeChar, &getQuoted, &getSeparator](
            const char* c_str)
    {
        std::string_view key {};
        const char* ptr = c_str;
        if ('"' == *ptr || '\'' == *ptr)
        {
            auto [endQuote, quoted] = getQuoted(ptr);
            // The key is valid only if valid only is followed by kvSeparator
            if (nullptr != endQuote
                && kvSeparator.compare(
                       1, kvSeparator.size(), endQuote, kvSeparator.size())
                       == 0)
            {
                key = std::move(quoted);
                ptr = endQuote + kvSeparator.size() + 1;
            }
        }
        else
        {
            ptr = getSeparator(ptr);

            if (nullptr != ptr)
            {
                // The key is valid only if no there a pairSeparator in the middle
                auto tmpKey = std::string_view(c_str, ptr - c_str);
                if (tmpKey.find(pairSeparator) == std::string_view::npos)
                {
                    key = std::move(tmpKey);
                    ptr += kvSeparator.size();
                }
                else
                {
                    ptr = nullptr;
                }
            }
        }
        return std::pair<const char*, std::string_view> {ptr, key};
    };

    /* -----------------------------------------------
                    Start parsing
     ----------------------------------------------- */
    bool isSearchComplete = false; // True if the search is complete successfully
    while (!isSearchComplete)
    {
        /* Get Key */
        auto [strParsePtr, key] = getKey(lastFoundOk);
        if (nullptr == strParsePtr || key.empty())
        {
            // Goback to the last valid pair
            if (lastFoundOk > *it)
            {
                isSearchComplete = true;
                lastFoundOk = lastFoundOk - pairSeparator.size();
            }
            // Fail to get key
            break;
        }

        // Get value
        std::string_view value {};
        // Check if value is quoted
        if ('"' == *strParsePtr || '\'' == *strParsePtr)
        {
            auto [endQuotePtr, quotedValue] = getQuoted(strParsePtr);
            if (nullptr != endQuotePtr)
            {
                value = std::move(quotedValue);
                // Point to the next char after the end quote
                strParsePtr = endQuotePtr + 1;
                // Check if the next string is a pairSeparator
                if (pairSeparator.compare(
                        0, pairSeparator.size(), strParsePtr, pairSeparator.size())
                    == 0)
                {
                    // Go to the next pair (next char after the pairSeparator)
                    strParsePtr += pairSeparator.size();
                }
                else
                {
                    // If there is no pairSeparator, the search is finished
                    isSearchComplete = true;
                }
            }
            else
            {
                // Fail to get value
                break;
            }
        }
        else
        {
            // Search for pairSeparator
            auto endValuePtr = strstr(strParsePtr, pairSeparator.data());
            if (nullptr != endValuePtr)
            {
                value = std::string_view(strParsePtr, endValuePtr - strParsePtr);
                // if there a endMapToken before the pairSeparator, the search is finished
                auto splitValue = value.find(endMapToken);
                if (splitValue != std::string_view::npos)
                {
                    value = value.substr(0, splitValue);
                    // Point to the endMapToken
                    strParsePtr = strParsePtr + splitValue;
                    isSearchComplete = true;
                }
                else
                {
                    // Point to the next char after the pairSeparator
                    strParsePtr = endValuePtr + pairSeparator.size();
                }
            }
            // No pairSeparator, search for endMapToken
            else if (endValuePtr = strchr(strParsePtr, endMapToken),
                     nullptr != endValuePtr)
            {
                value = std::string_view(strParsePtr, endValuePtr - strParsePtr);
                strParsePtr = endValuePtr;
                isSearchComplete = true;
                // Point to the next char after the endMapToken
                // No fail but search is complete ok
            }
            else
            {
                // No endMapToken, no pairSeparator, no end quoteChar
                break;
            }
        }
        // Print key and value and iterator
        lastFoundOk = strParsePtr;

        // Check the value type and cast it
        addValueToJson(outputDoc, key, value);
    }

    // Validate if the map is valid with the endMapToken
    if (isSearchComplete)
    {
        // Invalid endMapToken
        if (endMapToken != *lastFoundOk)
        {
            lastFoundOk = nullptr;
        }
    }
    else
    {
        lastFoundOk = nullptr; // Fail to parse the map
    }

    if (lastFoundOk)
    {
        rapidjson::StringBuffer s;
        rapidjson::Writer<rapidjson::StringBuffer> writer(s);
        outputDoc.Accept(writer);
        result[parser.name] = hlp::JsonString {s.GetString()};
        *it = lastFoundOk;
    }

    return (nullptr != lastFoundOk);
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

    std::string srcip {start, (size_t)((*it) - start)};
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
        // Format to strict_date_optional_time
        std::stringstream ssFormated;

        // Add year
        if (!fds.ymd.year().ok())
        {
            std::time_t t = std::time(nullptr);
            std::tm* const pTInfo = std::localtime(&t);
            fds.ymd = date::year_month_day(
                date::year(pTInfo->tm_year + 1900), fds.ymd.month(), fds.ymd.day());
        }

        auto durationMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(fds.tod.to_duration());
        date::hh_mm_ss<std::chrono::milliseconds> todF {durationMs};
        date::fields<std::chrono::milliseconds> fdsF(fds.ymd, fds.wd, todF);
        date::to_stream(ssFormated, "%Y-%m-%dT%H:%M:%SZ", fdsF);
        result[name] = ssFormated.str();
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
        // TODO: instead of defining the size directly we could look for the first
        //  occurrence of the endToken between all sizes of the tsExample
        for (auto i = 0; i < tsSize; i++, (*it)++)
        {
            if ('\0' == **it)
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
    while (**it != parser.endToken && '\0' != **it)
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
    char* str = nullptr;
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
    return ('9' >= c && '0' <= c);
}
static bool isAsciiUpp(char c)
{
    return ('Z' >= c && 'A' <= c);
}
static bool isAsciiLow(char c)
{
    return ('z' >= c && 'a' <= c);
}
static bool isDomainValidChar(char c)
{
    return (isAsciiNum(c) || isAsciiUpp(c) || isAsciiLow(c) || '-' == c || '_' == c
            || '.' == c);
}

bool parseDomain(const char** it, Parser const& parser, ParseResult& result)
{

    constexpr int kDomainMaxSize = 253;
    constexpr int kLabelMaxSize = 63;

    // TODO hack
    const bool validateFQDN = !parser.options.empty();

    const char* start = *it;
    while (**it != parser.endToken && '\0' != **it)
    {
        (*it)++;
    }
    std::string_view str {start, (size_t)((*it) - start)};

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

    const char* end = *it - endQuote.size();
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
    std::string_view str {start, (size_t)((*it) - start)};

    auto& trueVal = parser.options[0];
    result[parser.name] = bool {str == trueVal};
    return true;
}

// XML modules
using xmlModule = std::function<bool(pugi::xml_node&, json::Json&, std::string&)>;
static bool xmlWinModule(pugi::xml_node& node, json::Json& docJson, std::string path)
{
    if ("Data" != std::string {node.name()})
    {
        return false;
    }

    path += "/" + std::string {node.attribute("Name").value()};
    docJson.setString(node.text().as_string(), path);

    return true;
}

static std::unordered_map<std::string_view, xmlModule> xmlModules = {
    {"default", nullptr},
    {"windows", xmlWinModule},
};

// Xml module special rules
bool configureXmlParser(Parser& parser, std::vector<std::string_view> const& args)
{
    if (args.empty())
    {
        parser.options.push_back("default");
    }
    else if (args.size() == 1)
    {
        if (xmlModules.find(args[0]) != xmlModules.end())
        {
            parser.options.push_back(std::string {args[0]});
        }
        else
        {
            throw std::runtime_error {fmt::format(
                "Engine HLP specific parsers: Invalid \"xml\" parser: \"{}\".", args[0])};
        }
    }
    else
    {
        throw std::runtime_error {
            fmt::format("Engine HLP specific parsers: Invalid number of arguments for "
                        "\"xml\" parser. Expected 1 argument at most but got {}.",
                        args.size())};
    }

    return true;
}

/**
 * @brief Transform an XML document into a JSON document.
 *
 * @param doc Input XML document.
 * @param docJson Output JSON document.
 * @param path Path to the current node.
 */
static void xmlToJson(pugi::xml_node& docXml,
                      json::Json& docJson,
                      xmlModule mod,
                      std::string path = "")
{
    // TODO: add array support
    // Iterate over the xml generating the corresponding json
    for (auto node : docXml.children())
    {
        // Ignore text nodes as they are handled by the parent
        if (node.type() == pugi::node_pcdata)
        {
            continue;
        }

        std::string localPath {path};

        // Check if we have special rules and if are applied
        auto processed = false;
        if (mod)
        {
            processed = mod(node, docJson, localPath);
        }

        if (!processed)
        {
            localPath += "/" + std::string {node.name()};
            docJson.setObject(localPath);

            auto text = node.text();
            if (!text.empty())
            {
                docJson.setString(text.as_string(), localPath + "/#text");
            }

            for (auto attr : node.attributes())
            {
                docJson.setString(attr.value(), localPath + "/@" + attr.name());
            }
        }

        // Process children
        if (!node.first_child().empty())
        {
            xmlToJson(node, docJson, mod, localPath);
        }
    }
}

bool parseXml(const char** it, Parser const& parser, ParseResult& result)
{
    // TODO: same as parseJson, we are creating a Json object to obtain the json string
    // and later creating a Json object again, fix this on HLP refactor.
    bool success {false};
    pugi::xml_document xmlDoc; // = std::make_shared<pugi::xml_document>();
    json::Json jsonDoc;

    auto parseResult = xmlDoc.load_buffer(*it, strlen(*it));

    if (parseResult.status == pugi::status_ok)
    {
        xmlToJson(xmlDoc, jsonDoc, xmlModules[parser.options[0]]);
        result[parser.name] = jsonDoc;
        success = true;
        *it += strlen(*it);
    }

    return success;
}

bool parseCSV(const char** it, Parser const& parser, ParseResult& result)
{
    WAZUH_TRACE_FUNCTION;
    // RFC 4180
    const char separator = ',';
    const char escapeChar = '"'; // Escape character is the same as the double quote
    const char endToken = parser.endToken;

    rapidjson::Document outputDoc;
    outputDoc.SetObject();

    std::size_t colsQty = parser.options.size(); // Number of columns to parse
    std::size_t colsParsed = 0;                  // Number of columns parsed

    bool isExtractComplete = false; // true when the end of CSV and extraction is reached
    const char* str = *it;          // pointer to the current position in the string
    const bool separatorIsEndToken = (separator == endToken); // Special case

    /*
     * Returns pair <const char * iterator, std::string_view value> with
     * the pointer to the nex character to parse and the value quoted parsed
     * If the next character is not a separator or the end of the string, the cvs is not
     * valid
     */
    const auto getQuoted = [&](const char* str) -> std::pair<const char*, std::string>
    {
        str++;
        const char* end = nullptr;

        std::string value {};
        // Search for the end quote
        while (end = strchr(str, escapeChar), nullptr != end)
        {
            if (escapeChar == *(end + 1))
            {
                value.append(str, end + 1 - str);
                str = end + 2; // Escaped quote, skip it
            }
            else
            {
                // End quote found
                value.append(str, end - str);
                end++;
                break;
            }
        }
        return {end, std::move(value)};
    };

    /*
     * Returns pair <const char * iterator, std::string_view value> with
     * the pointer to the nex character to parse and the value unquoted parsed
     */
    const auto getUnQuoted = [&](const char* str) -> std::pair<const char*, std::string>
    {
        // Search for the separator or the end of the CSV.
        const char* end = strchr(str, separator);
        if (nullptr == end)
        {
            end = strchr(str, endToken);
        }
        // If the end is nullptr, the CSV is malformed
        if (nullptr != end)
        {
            std::string value(str, end - str);
            return {end, std::move(value)};
        }
        return {nullptr, std::string {}};
    };

    /*
     * Extract the values
     */

    if (separator == *str)
    { // First value can be empty
        addValueToJson(outputDoc, parser.options[colsParsed], "");
        colsParsed++;
        isExtractComplete = (colsParsed == colsQty) && endToken == *(str + 1);
    }
    while (!isExtractComplete && colsParsed < colsQty)
    {
        // get value
        std::string value {};
        switch (str[0])
        {
            case separator:
                // empty value
                str++;
                break;
            case escapeChar:
                // get value until next escapeChar
                std::tie(str, value) = getQuoted(str);
                break;
            default:
                // get value until next separator or end of CSV
                std::tie(str, value) = getUnQuoted(str);
                break;
        }

        /*
         * Check if the CSV is malformed:
         * - The value extracted is invalid
         * - The next character is not a separator or the end of the string
         */
        bool isInvalid = (nullptr == str) || ((separator != *str) && (endToken != *str));

        if (isInvalid)
        {
            break; // CSV is malformed
        }

        if (separator == *str)
        {
            // The next character must be a separator or the end of the CSV
            bool emptyValue = (separator == *(str + 1));
            // Or if the next value is the last value and is empty
            emptyValue |= ('\0' == *(str + 1));
            if (!emptyValue)
            {
                str++;
            }
            if (separatorIsEndToken && colsParsed + 1 == colsQty)
            {
                isExtractComplete = true;
            }
        }
        else
        {
            // The next character is the end of the CSV
            if (colsParsed + 1 != colsQty)
            {
                break; // Quanitity of columns does not match with the expected
            }
            isExtractComplete = true;
        }

        // Add value to the JSON
        addValueToJson(outputDoc, parser.options[colsParsed], value);
        colsParsed++; // new value parsed
    }

    // "CSV parsed successfully"
    if (isExtractComplete)
    {
        rapidjson::StringBuffer s;
        rapidjson::Writer<rapidjson::StringBuffer> writer(s);
        outputDoc.Accept(writer);
        result[parser.name] = hlp::JsonString {s.GetString()};
        *it = !separatorIsEndToken ? str : str - 1;
    }

    return isExtractComplete;
}
