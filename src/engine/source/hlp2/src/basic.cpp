#include "basic.hpp"
#include "fmt/format.h"
#include <date/date.h>
#include <date/tz.h>
#include <chrono>
#include <hlp/parsec.hpp>
#include <sstream>
#include <string>
#include <locale>
#include <sys/types.h>
#include <arpa/inet.h>
#include <json/json.hpp>
#include <optional>
#include <vector>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getBoolParser(Stop str, Options lst)
{
    return [](std::string_view text, int index)
    {
        if ( index > text.size())
            return parsec::makeError<json::Json>(fmt::format("Value is out of range in {}  at {}", text, index), text, index);

        if (text.find("true", index) == 0)
        {
            return parsec::makeSuccess<json::Json>(json::Json("true"), text, index + 4);
        }
        else if (text.find("false", index) == 0)
        {
            return parsec::makeSuccess<json::Json>(json::Json("false"), text, index + 5);
        }
        else
        {
            return parsec::makeError<json::Json>(fmt::format("Invalid input '{}'", text), text, index);
        }
    };
}


parsec::Parser<json::Json> getByteParser(Stop str, Options lst)
{
    return getNumericParser<int8_t>(str, lst);
}

parsec::Parser<json::Json> getLongParser(Stop str, Options lst)
{
    return getNumericParser<int64_t>(str, lst);
}

parsec::Parser<json::Json> getFloatParser(Stop str, Options lst)
{
    return getNumericParser<float_t>(str, lst);
}

parsec::Parser<json::Json> getDoubleParser(Stop str, Options lst)
{
    return getNumericParser<double_t>(str, lst);
}

parsec::Parser<json::Json> getScaledFloatParser(Stop str, Options lst)
{
    return getNumericParser<double_t>(str, lst);
}


parsec::Parser<json::Json> getTextParser(Stop str, Options lst)
{
    if ( ! str.has_value()) {
        throw std::invalid_argument(fmt::format("Text parser needs a stop string"));
    }
    auto stop = str.value();

    return [stop](std::string_view text, int index)
    {
        size_t pos = text.size();
        if (!stop.empty()) {
            pos = text.find(stop, index);
            if ( pos == std::string::npos) {
                return parsec::makeError<json::Json>( fmt::format("Unable to stop at '{}' string", stop), text, index);
            }
        }
        json::Json doc;
        auto t = text.substr(index, pos);
        // copy can be slow
        doc.setString(std::string{t});
        return parsec::makeSuccess<json::Json>(doc, text, pos);

    };
}


inline bool is_valid_base64_char(char c)
{
    if ((c >= 'A') && (c <= 'Z'))
    {
        return true;
    }

    if ((c >= 'a') && ('z'))
    {
        return true;
    }

    if ((c >= '0') && (c <= '9'))
    {
        return true;
    }

    if ((c == '+') || (c == '/'))
    {
        return true;
    }

    return false;
}


parsec::Parser<json::Json> getBinaryParser(Stop str, Options lst)
{
    return [](std::string_view text, int index)
    {

        auto it = std::find_if(std::begin(text)+index, std::end(text),
                         [](char c) { return !is_valid_base64_char(c); });

        auto size = it-std::begin(text);
        if (size == 0) {
            return parsec::makeError<json::Json>( fmt::format("Invalid char '{}' found at '{}'",*it, index), text, index);
        }
        // consume up to two '=' padding chars
        if (*it == '=')
        {
            size++;
            auto nx = std::next(it);
            if (*nx == '=')
                size++;
        }

        if ((size % 4) != 0)
        {
             return parsec::makeError<json::Json>( fmt::format("Wrong string size '{}' for base64 from offset {} to {}", size, index, size), text, index);
        }
        json::Json doc;
        // copy can be slow
        doc.setString(std::string{text.substr(index, size)});
        return parsec::makeSuccess<json::Json>(doc, text, size);
    };
}

/**
 * Receives twp options:
 *  0 - format string
 *  1 - locale string
 * @param str
 * @param lst
 * @return
 */
parsec::Parser<json::Json> getDateParser(Stop str, Options lst)
{

    if ( lst.size() != 2) {
        throw std::invalid_argument(fmt::format("date parser requires two parameters: locale and format"));
    }

    auto format = lst[0];
    std::locale locale;

    try {
        locale = std::locale(lst[1]);
    } catch (std::exception & e) {
        throw std::invalid_argument(fmt::format("Can't build date parser: {}", e.what()));
    }

    return [format, locale](std::string_view text, size_t index)
    {
        using namespace date;
        using namespace std::chrono;
        // copying strings could be slow
        // TODO: use from_chars as suggested in https://github.com/HowardHinnant/date/issues/413
        std::stringstream in {std::string{text}};
        in.imbue(locale);
        std::string abbrev;
        std::chrono::minutes offset{0};

        date::fields<std::chrono::nanoseconds> fds {};
        in >> date::parse(format, fds, abbrev, offset);
        if (in.fail())
        {
            return parsec::makeError<json::Json>(fmt::format("Error parsing '{}' date at {}",in.str(),in.tellg()),text, index);
        }
        // pos can be -1 if all the input has been consumed
        size_t pos = in.tellg() == std::string::npos ? (size_t)0 : (size_t)in.tellg();

        // if no year is parsed, we add our current year
        if (!fds.ymd.year().ok())
        {
            auto now = date::floor<date::days>(std::chrono::system_clock::now());
            auto ny = date::year_month_day{now}.year();
            fds.ymd = ny/fds.ymd.month()/fds.ymd.day();
        }

        auto tp = sys_days(fds.ymd) + fds.tod.to_duration();

        // Format to strict_date_optional_time
        std::ostringstream out;
        out.imbue(std::locale("en_US.UTF-8"));

        // If we have timezone information, transform it to UTC
        // else, assume we have UTC.
        //
        // If there is no timezone, we substract the offset to UTC
        // as default offset is 0
        auto tms = date::floor<std::chrono::milliseconds>(tp);
        if (!abbrev.empty())
        {
            // TODO: evaluate this function as it is constly
            // we might consider restrict the abbrev supported
            auto tz = date::make_zoned(abbrev, tms);
            date::to_stream(out, "%Y-%m-%dT%H:%M:%SZ", tz);
        } else
            date::to_stream(out, "%Y-%m-%dT%H:%M:%SZ", tms-offset);

        json::Json doc;
        doc.setString(out.str().data());
        if ( pos > text.size())
            return parsec::makeSuccess<json::Json>(doc,text, pos);

        return parsec::makeSuccess<json::Json>(doc,text, pos);
    };
}


parsec::Parser<json::Json> getIPParser(Stop str, Options lst)
{
    if ( ! str.has_value()) {
        throw std::invalid_argument(fmt::format("IP parser needs a stop string"));
    }
    auto stop = str.value();

    return [stop](std::string_view text, size_t index)
    {
        struct in_addr ip;
        struct in6_addr ipv6;
        std::string addr;
        unsigned long pos;

        if (stop.empty())
        {
            pos = text.size();
            addr = std::string {text};
        }
        else
        {
            pos = text.find(stop, index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("IP parser is unable to stop at '{}'", stop), text, index);
            }

            // copying strings can be slow
            addr = std::string {text.substr(index, pos)};
        }

        json::Json doc;

        if (inet_pton(AF_INET, addr.c_str(), &ip))
        {
            doc.setString(addr.data());
            return parsec::makeSuccess<json::Json>(doc,text, pos);
        }
        else if (inet_pton(AF_INET6, addr.c_str(), &ipv6))
        {
            doc.setString(addr.data());
            return parsec::makeSuccess<json::Json>(doc,text, pos);
        }

        return parsec::makeError<json::Json>( fmt::format("IP parser is unable to parse '{}' as IPv4 or IPv6",addr), text, index);

    };
}


} // HLP namespace



