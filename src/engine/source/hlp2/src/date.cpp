#include <chrono>
#include <locale>
#include <optional>
#include <stdexcept>
#include <vector>

#include <date/date.h>
#include <date/tz.h>
#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace hlp
{

namespace internal
{

/**
 * Supported formats, this will be injected by the config module in due time
 */
static const std::vector<std::tuple<std::string, std::string>> TimeFormat {
    {"ANSIC", "%a %b %d %T %Y"},        // Mon Jan _2 15:04:05 2006
    {"UnixDate", "%a %b %d %T %Z %Y"},  // Mon Jan _2 15:04:05 MST 2006
    {"RubyDate", "%a %b %d %T %z %Y"},  // Mon Jan 02 15:04:05 -0700 2006
    {"RFC822", "%d %b %y %R %Z"},       // 02 Jan 06 15:04 MST
    {"RFC822Z", "%d %b %y %R %z"},      // 02 Jan 06 15:04 -0000
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
    {"NGINX_ERROR", "%D %T"},                  // 10/25/2006 14:49:34
    {"POSTGRES", "%F %H:%M:%6S %Z"},           // 2021-02-14 10:45:33 UTC
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
std::string formatDateFromSample(std::string dateSample, std::string locale)
{

    // Check if the dateSample matches with more than one format
    std::vector<std::string> matchingFormats{};
    for (const auto& [name, format] : TimeFormat)
    {
        auto p = getDateParser({}, {}, Options {format, "en_US.UTF-8"});
        auto res = p(dateSample, 0);

        if (res.success())
        {
            if (res.index() != dateSample.size())
                throw std::runtime_error(
                    fmt::format("Failed to parse '{}', there is a partial match between "
                                "'0' and '{}'.",
                                dateSample,
                                res.index()));
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
} // namespace internal

parsec::Parser<json::Json> getDateParser(std::string name, Stop endTokens, Options lst)
{

    if (lst.size() == 0 || (lst.size() > 2) != 0)
    {
        throw std::runtime_error(
            "Date parser requires the first parameter to be a date sample or format. "
            "Additionally, it can be specified the \"locale\" as the second parameter, "
            "otherwise \"en_US.UTF-8\" will be used by default");
    }

    std::string format = lst[0];
    auto localeStr = lst.size() > 1 ? lst[1] : "en_US.UTF-8";

    std::locale locale;
    try
    {
        locale = std::locale(localeStr);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Can't build date parser, invalid locale: {}", e.what()));
    }

    // If not disabled automat then check if the format is a sample date
    if (format.find("%") == std::string::npos)
    {
        format = internal::formatDateFromSample(format, localeStr);
    }

    return [endTokens, format, locale, name](std::string_view text, size_t index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        // ----------------------------------
        //        Parse the date
        // ----------------------------------
        auto textRaw = std::get<std::string_view>(res);
        auto streamText = std::stringstream {textRaw.data()};
        streamText.imbue(locale);

        std::string abbrev{};
        std::chrono::minutes offset {0};
        date::fields<std::chrono::nanoseconds> fds {};
        streamText >> date::parse(format, fds, abbrev, offset);

        if (streamText.fail())
        {
            return parsec::makeError<json::Json>(fmt::format("{}: Expected a date", name),
                                                 index);
        }

        // Caculate the offset in the input string
        std::size_t endDatePos =
            (streamText.tellg() == std::string::npos)
                ? text.size()
                : static_cast<std::size_t>(streamText.tellg()) + index;

        // ----------------------------------
        //     Generate thw new date
        // ----------------------------------

        // if no year is parsed, we add our current year
        if (!fds.ymd.year().ok())
        {
            auto now = date::floor<date::days>(std::chrono::system_clock::now());
            auto ny = date::year_month_day {now}.year();
            fds.ymd = ny / fds.ymd.month() / fds.ymd.day();
        }

        auto tp = date::sys_days(fds.ymd) + fds.tod.to_duration();

        // Format to strict_date_optional_time
        std::ostringstream out{};
        out.imbue(std::locale("en_US.UTF-8"));

        // If we have timezone information, transform it to UTC
        // else, assume we have UTC.
        //
        // If there is no timezone, we substract the offset to UTC
        // as default offset is 0
        {
            auto tms = date::floor<std::chrono::milliseconds>(tp);
            if (!abbrev.empty())
            {
                // TODO: evaluate this function as it can be expensive
                // we might consider restrict the abbrev supported
                try
                {
                    auto tz = date::make_zoned(abbrev, tms);
                    date::to_stream(out, "%Y-%m-%dT%H:%M:%SZ", tz);
                }
                catch (std::exception& e)
                {
                    return parsec::makeError<json::Json>(
                        fmt::format("{}: {}", name, e.what()), index);
                }
            }
            else
            {
                date::to_stream(out, "%Y-%m-%dT%H:%M:%SZ", tms - offset);
            }
        }

        json::Json doc{};
        doc.setString(out.str().data());
        return parsec::makeSuccess<json::Json>(std::move(doc), endDatePos);
    };
}

} // namespace hlp
