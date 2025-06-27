/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TIME_HELPER_H
#define _TIME_HELPER_H

#include "stringHelper.h"
#include <chrono>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#if __cplusplus >= 201703L
#include <charconv>
#include <string_view>
#endif

#ifdef WIN32

static struct tm* gmtime_r(const time_t* timep, struct tm* result)
{
    errno = gmtime_s(result, timep);
    return errno == 0 ? result : nullptr;
}

static struct tm* localtime_r(const time_t* timep, struct tm* result)
{
    errno = localtime_s(result, timep);
    return errno == 0 ? result : nullptr;
}

#endif

namespace Utils
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

    static std::string getTimestamp(const std::time_t& time, const bool utc = true)
    {
        std::stringstream ss;
        struct tm buf;

        // gmtime: result expressed as a UTC time
        tm* localTime {utc ? gmtime_r(&time, &buf) : localtime_r(&time, &buf)};

        if (localTime == nullptr)
        {
            return "1970/01/01 00:00:00";
        }

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
    static std::string getCurrentTimestamp()
    {
        return getTimestamp(std::time(nullptr));
    }

    /**
     * @brief Get a compact timestamp.
     *
     * @param time Time to convert.
     * @param utc If true, the time will be expressed as a UTC time.
     * @return std::string Compact timestamp. Format: "YYYYMMDDhhmmss".
     */
    static std::string getCompactTimestamp(const std::time_t& time, const bool utc = true)
    {
        std::stringstream ss;
        struct tm buf;

        // gmtime: result expressed as a UTC time
        tm const* localTime {utc ? gmtime_r(&time, &buf) : localtime_r(&time, &buf)};

        if (localTime == nullptr)
        {
            return "1970/01/01 00:00:00";
        }

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

    static std::string getCurrentISO8601()
    {
        // Get local time in UTC
        auto now = std::chrono::system_clock::now();
        auto itt = std::chrono::system_clock::to_time_t(now);

        std::ostringstream ss;
        struct tm buf;
        tm* localTime = gmtime_r(&itt, &buf);

        if (localTime == nullptr)
        {
            return "1970/01/01 00:00:00";
        }

        ss << std::put_time(localTime, "%FT%T");

        // Get milliseconds from the current time
        auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

        // ISO 8601
        ss << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

        return ss.str();
    }

    static std::string timestampToISO8601(const std::string& timestamp)
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
        struct tm* localTime = gmtime_r(&time, &tm);

        if (localTime == nullptr)
        {
            return "";
        }

        output << std::put_time(localTime, "%FT%T");

        // Get milliseconds from the current time
        auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;

        // ISO 8601
        output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

        return output.str();
    }

    static std::string rawTimestampToISO8601(const std::string& timestamp)
    {
        if (timestamp.empty() || !Utils::isNumber(timestamp))
        {
            return "";
        }

        std::time_t time = std::stoi(timestamp);
        auto itt = std::chrono::system_clock::from_time_t(time);

        std::ostringstream output;
        struct tm buf;
        tm* localTime = gmtime_r(&time, &buf);

        if (localTime == nullptr)
        {
            return "";
        }

        output << std::put_time(localTime, "%FT%T");

        // Get milliseconds from the current time
        auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;

        // ISO 8601
        output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

        return output.str();
    }

    static std::string rawTimestampToISO8601(const double timestamp)
    {
        std::time_t time = timestamp;
        auto itt = std::chrono::system_clock::from_time_t(time);

        std::ostringstream output;
        struct tm buf;
        tm* localTime = gmtime_r(&time, &buf);

        if (localTime == nullptr)
        {
            return "";
        }

        output << std::put_time(localTime, "%FT%T");

        if (timestamp - static_cast<int>(timestamp) == 0)
        {
            // Get milliseconds from the current time
            auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;

            // ISO 8601
            output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';
        }
        else
        {
            output << '.' << std::setfill('0') << std::setw(3)
                   << static_cast<int>(std::round((timestamp - static_cast<int>(timestamp)) * 1000)) << 'Z';
        }

        return output.str();
    }

    /**
     * @brief Get seconds from epoch, since 1970-01-01 00:00:00 UTC.
     * @return seconds from epoch.
     */
    static int64_t getSecondsFromEpoch()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    };

#if __cplusplus >= 201703L
    static std::string rawTimestampToISO8601(std::string_view timestamp)
    {
        if (timestamp.empty() || !Utils::isNumber(timestamp))
        {
            return "";
        }
        std::time_t time;

        auto [ptr, ec] = std::from_chars(timestamp.data(), timestamp.data() + timestamp.size(), time);
        if (ec != std::errc())
        {
            return "";
        }

        auto itt = std::chrono::system_clock::from_time_t(time);

        std::ostringstream output;
        struct tm buf;
        tm* localTime = gmtime_r(&time, &buf);

        if (localTime == nullptr)
        {
            return "";
        }

        output << std::put_time(localTime, "%FT%T");

        // Get milliseconds from the current time
        auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;

        // ISO 8601
        output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

        return output.str();
    }
#endif

#pragma GCC diagnostic pop
} // namespace Utils

#endif // _TIME_HELPER_H
