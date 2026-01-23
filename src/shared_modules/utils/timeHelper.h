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
#include <regex>
#if __cplusplus >= 201703L
#include <charconv>
#include <string_view>
#endif

#define ISO8601_LENGTH_WITH_MS 24
#define ISO8601_LENGTH_NO_MS 20

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

    /**
     * @brief Get a timestamp.
     *
     * @param time Time to convert.
     * @param utc If true, the time will be expressed as a UTC time.
     * @return std::string Timestamp. Format: "YYYY/MM/DD hh:mm:ss".
     */
    static std::string getTimestamp(const std::time_t& time, const bool utc = true)
    {
        std::stringstream ss;
        struct tm buf
        {
        };

        // gmtime: result expressed as a UTC time
        tm const* localTime {utc ? gmtime_r(&time, &buf) : localtime_r(&time, &buf)};

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

    /**
     * @brief Get the current timestamp.
     */
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
        struct tm buf
        {
        };

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

    /**
     * @brief Get the current compact timestamp.
     */
    static std::string getCurrentISO8601()
    {
        // Get local time in UTC
        auto now = std::chrono::system_clock::now();
        auto itt = std::chrono::system_clock::to_time_t(now);

        std::ostringstream ss;
        struct tm buf
        {
        };
        tm const* localTime = gmtime_r(&itt, &buf);

        if (localTime == nullptr)
        {
            return "1970/01/01 00:00:00";
        }

        ss << std::put_time(localTime, "%Y-%m-%dT%H:%M:%S");

        // Get milliseconds from the current time
        auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

        // ISO 8601
        ss << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

        return ss.str();
    }

    /**
     * @brief Convert a timestamp to ISO8601 format.
     *
     * @param timestamp Timestamp to convert. Format: "YYYY/MM/DD hh:mm:ss".
     * @return std::string ISO8601 timestamp.
     */
    static std::string timestampToISO8601(const std::string& timestamp)
    {
        // Accepts: YYYY-MM-DDTHH:MM:SS(.mmm)?Z
        static const std::regex iso8601_regex(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$")");
        if (std::regex_match(timestamp, iso8601_regex))
        {
            return timestamp;
        }

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
        struct tm const* localTime = gmtime_r(&time, &tm);

        if (localTime == nullptr)
        {
            return "";
        }

        output << std::put_time(localTime, "%Y-%m-%dT%H:%M:%S");

        // Get milliseconds from the current time
        auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;

        // ISO 8601
        output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';

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

    /**
     * @brief Check if a timestamp is in ISO8601 format.
     * @param timestamp Timestamp to check.
     * @return std::string ISO8601 timestamp or empty string.
     */
    static std::string normalizeTimestampISO8601(const std::string& timestamp)
    {
        // "2024-11-14T18:32:28Z"
        // "2025-11-26T12:00:01.000Z"
        const int size = static_cast<int>(timestamp.size());
        if (size != ISO8601_LENGTH_WITH_MS && size != ISO8601_LENGTH_NO_MS)
        {
            return "";
        }

        for (int i = 0; i < size; ++i)
        {
            // Check - exists on expected positions.
            if ((i == 4 || i == 7) && timestamp[i] != '-')
            {
                return "";
            }
            // Check T exists on expected position.
            else if (i == 10 && timestamp[i] != 'T')
            {
                return "";
            }
            // Check : exists on expected positions.
            else if ((i == 13 || i == 16) && timestamp[i] != ':')
            {
                return "";
            }
            // Check Z exists on expected position if no milliseconds and add default milliseconds.
            else if (size == ISO8601_LENGTH_NO_MS && i == 19)
            {
                if (timestamp[i] != 'Z')
                {
                    return "";
                }
                // Adds milliseconds to a valid ISO8601 without milliseconds.
                auto tempTimestamp {timestamp};
                Utils::replaceFirst(tempTimestamp, "Z", ".000Z");
                return tempTimestamp;
            }
            // Check . exists on expected position if milliseconds.
            else if (size == ISO8601_LENGTH_WITH_MS && i == 19 && timestamp[i] != '.')
            {
                return "";
            }
            // Check Z exists on expected position if milliseconds.
            else if (size == ISO8601_LENGTH_WITH_MS && i == 23 && timestamp[i] != 'Z')
            {
                return "";
            }
            // Check digits on expected positions.
            else if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 && i != 19 && i != 23)
            {
                if (!std::isdigit(timestamp[i]))
                {
                    return "";
                }
            }
        }

        return timestamp;
    }

#if __cplusplus >= 201703L
    /**
     * @brief Convert a raw timestamp to ISO8601 format.
     * @param timestamp Timestamp to convert. Can be uint32_t, double, std::string or std::string_view.
     * @return std::string ISO8601 timestamp or empty string.
     */
    template<typename T>
    static std::string rawTimestampToISO8601(T timestamp)
    {
        static_assert(std::is_same_v<std::decay_t<T>, uint32_t> || std::is_same_v<std::decay_t<T>, double> ||
                          std::is_same_v<std::decay_t<T>, std::string> ||
                          std::is_same_v<std::decay_t<T>, std::string_view>,
                      "Invalid timestamp type");
        if constexpr (std::is_same_v<std::decay_t<T>, uint32_t>)
        {
            std::time_t time = timestamp;
            auto itt = std::chrono::system_clock::from_time_t(time);
            std::ostringstream output;
            struct tm buf
            {
            };
            tm const* localTime = gmtime_r(&time, &buf);
            if (localTime == nullptr)
            {
                return "";
            }
            output << std::put_time(localTime, "%Y-%m-%dT%H:%M:%S");
            // Get milliseconds from the current time
            auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;
            // ISO 8601
            output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';
            return output.str();
        }
        else if constexpr (std::is_same_v<std::decay_t<T>, double>)
        {
            std::time_t time = timestamp;
            auto itt = std::chrono::system_clock::from_time_t(time);
            std::ostringstream output;
            struct tm buf
            {
            };
            tm const* localTime = gmtime_r(&time, &buf);
            if (localTime == nullptr)
            {
                return "";
            }
            output << std::put_time(localTime, "%Y-%m-%dT%H:%M:%S");
            if (std::abs(timestamp - static_cast<int>(timestamp)) < 1e-9)
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
        else if constexpr (std::is_same_v<std::decay_t<T>, std::string>)
        {
            if (timestamp.empty() || !Utils::isNumber(timestamp))
            {
                // Check if timestamp has the format "YYYY/MM/DD hh:mm:ss"
                // if not, check if it is already ISO8601.
                auto ISO8601Timestamp = timestampToISO8601(timestamp);
                return ISO8601Timestamp.empty() ? normalizeTimestampISO8601(timestamp) : std::move(ISO8601Timestamp);
            }
            std::time_t time = std::stoi(timestamp);
            auto itt = std::chrono::system_clock::from_time_t(time);
            std::ostringstream output;
            struct tm buf
            {
            };
            tm const* localTime = gmtime_r(&time, &buf);
            if (localTime == nullptr)
            {
                return "";
            }
            output << std::put_time(localTime, "%Y-%m-%dT%H:%M:%S");
            // Get milliseconds from the current time
            auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;
            // ISO 8601
            output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';
            return output.str();
        }
        else if constexpr (std::is_same_v<std::decay_t<T>, std::string_view>)
        {
            if (timestamp.empty() || !Utils::isNumber(timestamp))
            {
                // Check if timestamp has the format "YYYY/MM/DD hh:mm:ss"
                // if not, check if it is already ISO8601.
                auto ISO8601Timestamp = timestampToISO8601(std::string(timestamp));
                return ISO8601Timestamp.empty() ? normalizeTimestampISO8601(std::string(timestamp)) : std::move(ISO8601Timestamp);
            }
            std::time_t time;
            auto [ptr, ec] = std::from_chars(timestamp.data(), timestamp.data() + timestamp.size(), time);
            if (ec != std::errc())
            {
                return "";
            }
            auto itt = std::chrono::system_clock::from_time_t(time);
            std::ostringstream output;
            struct tm buf
            {
            };
            tm const* localTime = gmtime_r(&time, &buf);
            if (localTime == nullptr)
            {
                return "";
            }
            output << std::put_time(localTime, "%Y-%m-%dT%H:%M:%S");
            // Get milliseconds from the current time
            auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(itt.time_since_epoch()).count() % 1000;
            // ISO 8601
            output << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';
            return output.str();
        }
        else
        {
            return "";
        }
    }
#endif

#pragma GCC diagnostic pop
} // namespace Utils

#endif // _TIME_HELPER_H
