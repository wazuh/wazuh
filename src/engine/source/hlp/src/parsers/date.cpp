#include <chrono>
#include <locale>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <curl/curl.h>
#include <date/date.h>
#include <date/tz.h>

#include <base/logging.hpp>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getMapper(std::string&& parsed, std::string_view targetField)
{
    return [parsed = std::move(parsed), targetField](json::Json& event)
    {
        event.setString(parsed, targetField);
    };
}

SemParser getSemParser(std::string_view targetField,
                       date::fields<std::chrono::nanoseconds> fds,
                       const std::locale& outputLocale,
                       std::string&& abbrev,
                       std::string_view name,
                       std::chrono::minutes offset)
{

    return [targetField, fds, outputLocale, abbrev = std::move(abbrev), name, offset](
               std::string_view) -> std::variant<hlp::parser::Mapper, base::Error>
    {
        // if no year is parsed, we add our current year
        date::year_month_day ymd = fds.ymd;
        if (!fds.ymd.year().ok())
        {
            auto now = date::floor<date::days>(std::chrono::system_clock::now());
            auto ny = date::year_month_day {now}.year();
            ymd = ny / fds.ymd.month() / fds.ymd.day();
        }

        auto tp = date::sys_days(ymd) + fds.tod.to_duration();

        // Format to strict_date_optional_time
        std::ostringstream out {};
        out.imbue(outputLocale);

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
                    return base::Error {fmt::format("{} failed to set timezone: {}", name, e.what())};
                }
            }
            else
            {
                date::to_stream(out, "%Y-%m-%dT%H:%M:%SZ", tms - offset);
            }
        }

        if (targetField.empty())
        {
            return noMapper();
        }
        return getMapper(out.str(), targetField);
    };
}

/**
 * Supported formats, this will be injected by the config module in due time
 */
const std::vector<std::tuple<std::string, std::string>> TIME_FORMAT {
    {"ANSIC", "%a %b %d %T %Y"},        // Mon Jan _2 15:04:05 2006
    {"UnixDate", "%a %b %d %T %Z %Y"},  // Mon Jan _2 15:04:05 MST 2006
    {"RubyDate", "%a %b %d %T %z %Y"},  // Mon Jan 02 15:04:05 -0700 2006
    {"RFC822", "%d %b %y %R %Z"},       // 02 Jan 06 15:04 MST
    {"RFC822Z", "%d %b %y %R %z"},      // 02 Jan 06 15:04 -0000
    {"RFC850", "%A, %d-%b-%y %T %Z"},   // Monday, 02-Jan-06 15:04:05 MST
    {"RFC1123", "%a, %d %b %Y %T %Z"},  // Mon, 02 Jan 2006 15:04:05 MST
    {"RFC1123Z", "%a, %d %b %Y %T %z"}, // Mon, 02 Jan 2006 15:04:05 -0700
    {"RFC3339", "%FT%TZ%Ez"},           // 2006-01-02T15:04:05Z07:00
    {"RFC3164", "%b %d %R:%6S %Z"},     // Mar  1 18:48:50.483 UTC
    {"SYSLOG", "%b %d %T"},             // Jun 14 15:16:01
    {"ISO8601", "%FT%T%Ez"},            // 2018-08-14T14:30:02.203151+02:00
    {"ISO8601Z", "%FT%TZ"},             // 2018-08-14T14:30:02.203151Z
    {"HTTPDATE", "%d/%b/%Y:%T %z"},     // 26/Dec/2016:16:22:14 +0000
    // HTTP-date = rfc1123-date |rfc850-date | asctime-date
    {"NGINX_ERROR", "%Y/%m/%d %T"},  // 2019/10/30 23:26:34
    {"POSTGRES", "%F %H:%M:%6S %Z"}, // 2021-02-14 10:45:33 UTC
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
// TODO: Delete option for locale
std::string formatDateFromSample(const std::string& dateSample)
{

    // Check if the dateSample matches with more than one format
    std::vector<std::string> matchingFormats {};
    for (const auto& [name, format] : TIME_FORMAT)
    {
        auto p = hlp::parsers::getDateParser({.options = {format}});
        auto res = p(dateSample);

        if (res.success())
        {
            if (!res.remaining().empty())
            {
                throw std::runtime_error(
                    fmt::format("Failed to parse '{}', remaining: '{}'", dateSample, res.remaining()));
            }

            matchingFormats.push_back(format);
        }
    }

    if (matchingFormats.empty())
    {
        throw std::runtime_error(fmt::format("Failed to parse '{}', no matching format found", dateSample));
    }
    else if (matchingFormats.size() > 1)
    {
        throw std::runtime_error(fmt::format(
            "Failed to parse '{}'. Multiple formats match: {}", dateSample, fmt::join(matchingFormats, ", ")));
    }

    // Return the matching format
    return matchingFormats[0];
}
} // namespace

namespace hlp
{

namespace
{
/**
 * @brief Try load and check if the timezone database needs to be updated.
 *
 * @param version Required version
 * @param autoUpdate if true, check if the database needs to be updated
 * @return False if the database needs to be downloaded and installed/updated.
 * @return True if the database is loaded correctly and no update is needed.
 */
bool loadTimeZoneDB(const std::string& version, bool autoUpdate)
{
    try
    {
        const auto& db = date::get_tzdb();
        LOG_INFO("Loaded timezone database version: '{}'", db.version);
        return !(autoUpdate && db.version != version);
    }
    catch (std::exception& e)
    {
        LOG_WARNING("Failed to load timezone database: '{}', try to download it", e.what());
        return false;
    }
}

/**
 * @brief Download and install the timezone database.
 *
 * @param version The version to download
 * @note Date library is compiled with AUTO_DOWNLOAD=0 and HAS_REMOTE_API=1
 */
void downloadAndInstallTimeZoneDB(const std::string& version)
{
    std::array<char, CURL_ERROR_SIZE> errorBuffer {};
    LOG_TRACE("Downloading timezone database");

    if (!date::remote_download(version, errorBuffer.data()))
    {
        LOG_WARNING("Failed to download timezone database: '{}'", errorBuffer.data());
        return;
    }

    if (!date::remote_install(version))
    {
        LOG_WARNING("Failed to install timezone database.");
        return;
    }

    date::reload_tzdb();
}
} // namespace

void initTZDB(const std::string& path, const bool autoUpdate)
{
    date::set_install(path);

    std::string rv = "2024a"; // TODO: change to date::remote_version();
    LOG_DEBUG("Remote timezone database version: '{}'", rv);

    if (loadTimeZoneDB(rv, autoUpdate))
    {
        return;
    }

    downloadAndInstallTimeZoneDB(rv);
    const auto& db = date::get_tzdb(); // Check if the database is loaded correctly
    LOG_INFO("Timezone database updated to version: '{}'", db.version);
}

namespace parsers
{
Parser getDateParser(const Params& params)
{

    if (params.options.empty() || (params.options.size() > 2))
    {
        throw std::runtime_error("Date parser requires the first parameter to be a date sample or format. "
                                 "Additionally, it can be specified the \"locale\" as the second parameter, "
                                 "otherwise \"C/POSIX\" will be used by default");
    }

    std::string format = params.options[0];
    auto localeStr = params.options.size() > 1 ? params.options[1] : "_auto";

    std::locale parserLocale;                          // Used for parsing the date
    std::locale outputLocale = std::locale::classic(); // Used for outputting the date
    try
    {
        // Use the C/POSIX locale.
        parserLocale = localeStr == "_auto" ? std::locale::classic() : std::locale(localeStr);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(fmt::format("Can't build date parser, locale '{}' not found", localeStr));
    }

    // If not disabled automat then check if the format is a sample date
    if (format.find('%') == std::string::npos)
    {
        auto it = std::find_if(TIME_FORMAT.begin(),
                               TIME_FORMAT.end(),
                               [format](const std::tuple<std::string, std::string>& tuple)
                               { return std::get<0>(tuple) == format; });
        if (it != TIME_FORMAT.end())
        {
            format = std::get<1>(*it);
        }
        else
        {
            format = formatDateFromSample(format);
        }
    }

    const auto target = params.targetField.empty() ? std::string {} : params.targetField;

    return [format, parserLocale, outputLocale, name = params.name, target](std::string_view text)
    {
        auto ss = std::istringstream(std::string(text));
        ss.imbue(parserLocale);

        std::string abbrev {};
        std::chrono::minutes offset {0};
        date::fields<std::chrono::nanoseconds> fds {};
        ss >> date::parse(format, fds, abbrev, offset);

        if (ss.fail())
        {
            return abs::makeFailure<ResultT>(text, name);
        }

        auto pos = (ss.tellg() == -1) ? text.size() : static_cast<std::size_t>(ss.tellg());

        return abs::makeSuccess(
            SemToken {text.substr(0, pos), getSemParser(target, fds, outputLocale, std::move(abbrev), name, offset)},
            text.substr(pos));
    };
}

} // namespace parsers
} // namespace hlp
