#include "fmt/format.h"
#include "stream_view.hpp"
#include <chrono>
#include <date/date.h>
#include <date/tz.h>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <locale>
#include <optional>
#include <vector>
#include <hlp/hlp.hpp>
#include <stdexcept>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

namespace internal
{

/**
 * Supported formats, this will be injected by the config module in due time
 */
static const std::vector<std::tuple<std::string, std::string>> TimeFormat {
    {"ANSIC", "%a %b %d %T %Y"},        // Mon Jan _2 15:04:05 2006
    {"UnixDate", "%a %b %d %T %Y"},     // Mon Jan _2 15:04:05 MST 2006
    {"RubyDate", "%a %b %d %T %z %Y"},  // Mon Jan 02 15:04:05 -0700 2006
    {"RFC822", "%d %b %y %R %Z"},       // 02 Jan 06 15:04 MST
    {"RFC822Z", "%d %b %y %R %z"},      // 02 Jan 06 15:04 MST
    {"RFC850", "%A, %d-%b-%y %T %Z"},   // Monday, 02-Jan-06 15:04:05 MST
    {"RFC1123", "%a, %d %b %Y %T %Z"},  // Mon, 02 Jan 2006 15:04:05 MST
    {"RFC1123Z", "%a, %d %b %Y %T %z"}, // Mon, 02 Jan 2006 15:04:05 -0700
    {"RFC3339", "%FT%TZ%Ez"},           // 2006-01-02T15:04:05Z07:00
    {"RFC3154", "%b %d %R:%6S %Z"},     // Mar  1 18:48:50.483 UTC
    {"SYSLOG", "%b %d %T"},             // Jun 14 15:16:01
    {"ISO8601", "%FT%T%Ez"},            // 2018-08-14T14:30:02.203151+02:00
    {"ISO8601Z", "%FT%TZ"},             // 2018-08-14T14:30:02.203151Z
    {"HTTPDATE", "%d/%b/%Y:%T %z"},     // 26/Dec/2016:16:22:14 +0000
    // HTTP-date = rfc1123-date |rfc850-date | asctime-date
    {"NGINX_ERROR", "%D %T"},                  // 2016/10/25 14:49:34
    {"APACHE_ERROR", "%a %b %d %H:%M.%9S %Y"}, // Mon Dec 26 16:15:55.103786 2016
    {"POSTGRES", "%F %H:%M.%6S %Z"},           // 2021-02-14 10:45:33 UTC
};


/**
 * @brief Get the date format in snprintf format of the sample date string.
 *
 * i.e. 2020-01-01T00:00:00Z returns %Y-%m-%dT%H:%M:%SZ </br>
 * If the sample date string is not valid or matches with more than one format,
 * an base::Error with description is returned.
 *
 * @param dateSample
 * @return std::variant<std::string, base::Error>
 */
std::string formatDateFromSample(std::string dateSample, std::string locale) {

    // Check if the dateSample matches with more than one format
    std::vector<std::string> matchingFormats;
    for (const auto& [name,format] : TimeFormat)
    {
        auto p = getDateParser({}, Options{format,"en_US.UTF-8"});
        auto res = p(dateSample, 0);

        if (res.success())
        {
            if (res.index != dateSample.size())
                throw std::runtime_error(
                    fmt::format("Failed to parse '{}', there is a partial match between '0' and '{}'.", dateSample, res.index));
            matchingFormats.push_back(format);
        }
    }

    if (matchingFormats.size() == 0)
    {
        throw std::runtime_error(
            fmt::format("Failed to parse '{}', no matching format found", dateSample));
    }
    else if (matchingFormats.size() > 1)
    {
        throw std::runtime_error(
            fmt::format("Failed to parse '{}'. Multiple formats match: {}",
                        dateSample,
                        fmt::join(matchingFormats, ", ")));
    }

    // Return the matching format
    return matchingFormats[0];
}
} // namespace date


parsec::Parser<json::Json> getDateParser(Stop str, Options lst)
{

    if (lst.size() == 0 || lst.size() > 2)
    {
        throw std::invalid_argument(
            fmt::format("date parser requires as parameters either date sample, or a format, or a format and a locale"));
    }

    std::string format = lst[0];
    std::string localeStr = "en_US.UTF-8";

    if (lst.size() == 2 )
            localeStr = lst[1];

    std::locale locale;
    try
    {
        locale = std::locale(localeStr);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(fmt::format("Can't build date parser: {}", e.what()));
    }

    if (format.find("%") == std::string::npos)
        format = internal::formatDateFromSample(format, localeStr);


    return [str, format, locale](std::string_view text, size_t index)
    {
        using namespace date;
        using namespace std::chrono;

        size_t pos = text.size();
        std::string_view fp = text.substr(index);
        if (str.has_value() && ! str.value().empty())
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            fp = text.substr(index, pos);
        }

        // TODO: tellg returns incorrect position with view_istream<char>
        // view_istream<char> in(fp);
        std::stringstream in{fp.data()};
        in.imbue(locale);
        std::string abbrev;
        std::chrono::minutes offset {0};

        date::fields<std::chrono::nanoseconds> fds {};
        in >> date::parse(format, fds, abbrev, offset);
        if (in.fail())
        {
            return parsec::makeError<json::Json>(
                fmt::format("Error parsing '{}' date at {}", text, in.tellg()),
                text,
                index);
        }
        // pos can be -1 if all the input has been consumed
        pos = in.tellg() == std::string::npos ? text.size() : (size_t)in.tellg()+index;

        // if no year is parsed, we add our current year
        if (!fds.ymd.year().ok())
        {
            auto now = date::floor<date::days>(std::chrono::system_clock::now());
            auto ny = date::year_month_day {now}.year();
            fds.ymd = ny / fds.ymd.month() / fds.ymd.day();
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
            // TODO: evaluate this function as it can be expensive
            // we might consider restrict the abbrev supported
            auto tz = date::make_zoned(abbrev, tms);
            date::to_stream(out, "%Y-%m-%dT%H:%M:%SZ", tz);
        }
        else
            date::to_stream(out, "%Y-%m-%dT%H:%M:%SZ", tms - offset);

        json::Json doc;
        doc.setString(out.str().data());
        if (pos > text.size())
            return parsec::makeSuccess<json::Json>(doc, text, pos);

        return parsec::makeSuccess<json::Json>(doc, text, pos);
    };
}

} // namespace hlp
