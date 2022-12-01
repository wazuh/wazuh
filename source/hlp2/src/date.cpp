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

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

namespace internal
{

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
std::variant<std::string, base::Error> formatDateFromSample(std::string dateSample) {

    // Known formats
    // https://howardhinnant.github.io/date/date.html#from_stream_formatting
    std::vector<std::string> knownFormats = {
        "%m/%d/%y",
        "%d/%m/%y",
        "%Y-%m-%dT%H:%M:%S%Z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z"
    };

    // Check if the dateSample matches with format
    auto checkFormat = [](const std::string& format,
                          const std::string& sample) -> bool
    {
        std::istringstream ss(sample);
        std::chrono::nanoseconds s {};
        //date::sys_time<std::chrono::nanoseconds> s {};

        ss >> date::parse(format, s);

        if (ss.fail()) {
            return false;
        }
        else if (ss.eof()) {
            return true;
        }
        else {
            return false;
        }
    };


    // Check if the dateSample matches with more than one format
    std::vector<std::string> matchingFormats;
    for (const auto& format : knownFormats)
    {
        if (checkFormat(format, dateSample))
        {
            matchingFormats.push_back(format);
        }
    }

    if (matchingFormats.size() == 0)
    {
        return base::Error {
            fmt::format("Failed to parse '{}', no matching format found", dateSample)};
    }
    else if (matchingFormats.size() > 1)
    {
        return base::Error {
            fmt::format("Failed to parse '{}'. Multiple formats match: {}",
                        dateSample,
                        fmt::join(matchingFormats, ", "))};
    }

    // Return the matching format
    return matchingFormats[0];
}
} // namespace date


parsec::Parser<json::Json> getDateParser(Stop str, Options lst)
{

    if (lst.size() != 2)
    {
        throw std::invalid_argument(
            fmt::format("date parser requires parameters format and locale"));
    }

    auto format = lst[0];
    std::locale locale;

    try
    {
        locale = std::locale(lst[1]);
    }
    catch (std::exception& e)
    {
        throw std::invalid_argument(fmt::format("Can't build date parser: {}", e.what()));
    }

    return [str, format, locale](std::string_view text, size_t index)
    {
        using namespace date;
        using namespace std::chrono;

        size_t pos = text.size();
        std::string_view fp = text;
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

        view_istream<char> in(fp);
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
        pos = in.tellg() == std::string::npos ? (size_t)0 : (size_t)in.tellg();

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
