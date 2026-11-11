// SPDX-License-Identifier: AGPL-3.0-or-later
#include "base/utils/timeUtils.hpp"

#include "base/utils/stringUtils.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

#include <fmt/format.h>

namespace base::utils::time
{

std::string getTimestamp(const std::time_t& time, const bool utc)
{
    std::stringstream ss;
    // gmtime: result expressed as a UTC time
    tm* localTime {utc ? gmtime(&time) : localtime(&time)};
    // Final timestamp: "YYYY/MM/DD hh:mm:ss"
    // Date
    ss << std::setfill('0') << std::setw(4) << std::to_string(localTime->tm_year + 1900);
    ss << "/";
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_mon + 1);
    ss << "/";
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_mday);
    // Time
    ss << " ";
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_hour);
    ss << ":";
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_min);
    ss << ":";
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_sec);
    return ss.str();
}
std::string getCurrentTimestamp()
{
    return getTimestamp(std::time(nullptr));
}

std::string getCurrentDate(const std::string& separator)
{
    auto date = base::utils::string::split(getCurrentTimestamp(), ' ').at(0);
    base::utils::string::replaceAll(date, "/", separator);

    return date;
}

std::string getCompactTimestamp(const std::time_t& time, const bool utc)
{
    std::stringstream ss;
    // gmtime: result expressed as a UTC time
    tm const* localTime {utc ? gmtime(&time) : localtime(&time)};
    // Date
    ss << std::setfill('0') << std::setw(4) << std::to_string(localTime->tm_year + 1900);
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_mon + 1);
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_mday);
    // Time
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_hour);
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_min);
    ss << std::setfill('0') << std::setw(2) << std::to_string(localTime->tm_sec);
    return ss.str();
}

std::string getCurrentISO8601()
{
    // Get local time in UTC
    auto now = std::chrono::system_clock::now();
    auto itt = std::chrono::system_clock::to_time_t(now);

    std::ostringstream ss;
    ss << std::put_time(gmtime(&itt), "%FT%T");

    // Get milliseconds from the current time
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

    // ISO 8601
    ss << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

    return ss.str();
}

int64_t systemEpochNanos() noexcept
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t StrictlyIncreasingClock::next(int64_t now) noexcept
{
    auto last = m_last.load(std::memory_order_acquire);
    while (true)
    {
        // On CAS failure `last` is reloaded with the current value; recompute the candidate.
        const auto cand = std::max(now, last + 1);
        if (m_last.compare_exchange_weak(last, cand, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return cand;
        }
    }
}

StrictlyIncreasingClock& receptionClock()
{
    static StrictlyIncreasingClock clock;
    return clock;
}

std::string epochNanosToISO8601(int64_t nanos)
{
    constexpr int64_t NS = 1'000'000'000;

    // Floor division so the fractional part is always in [0, NS)
    auto secs = nanos / NS;
    auto rest = nanos % NS;
    if (rest < 0)
    {
        secs -= 1;
        rest += NS;
    }

    std::time_t t = secs;
    std::tm tm {};
    gmtime_r(&t, &tm);

    char buf[32];
    std::strftime(buf, sizeof buf, "%FT%T", &tm);

    return fmt::format("{}.{:09d}Z", buf, rest);
}

std::string timestampToISO8601(const std::string& timestamp)
{
    std::tm tm {};
    std::istringstream ss(timestamp);
    ss >> std::get_time(&tm, "%Y/%m/%d %H:%M:%S");
    if (ss.fail())
    {
        return "";
    }
    std::time_t time = std::mktime(&tm);

    auto itt = std::chrono::system_clock::from_time_t(time);

    std::ostringstream output;
    output << std::put_time(gmtime(&time), "%FT%T");

    // Get milliseconds from the current time
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;

    // ISO 8601
    output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

    return output.str();
}

std::string rawTimestampToISO8601(const std::string& timestamp)
{
    if (timestamp.empty() || !base::utils::string::isNumber(timestamp))
    {
        return "";
    }

    std::time_t time = std::stoi(timestamp);
    auto itt = std::chrono::system_clock::from_time_t(time);

    std::ostringstream output;
    output << std::put_time(gmtime(&time), "%FT%T");

    // Get milliseconds from the current time
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;

    // ISO 8601
    output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

    return output.str();
}

std::chrono::seconds secondsSinceEpoch()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
}

int64_t getSecondsFromEpoch()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
};

} // namespace base::utils::time
