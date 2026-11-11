// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

#ifndef _TIME_UTILS_HPP
#define _TIME_UTILS_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

namespace base::utils::time
{

/**
 * @brief Get a formatted timestamp string from a time_t value.
 *
 * @param time The time value.
 * @param utc If true, use UTC; otherwise use local time.
 * @return std::string Formatted as "YYYY/MM/DD hh:mm:ss".
 */
std::string getTimestamp(const time_t& time, bool utc = true);

/**
 * @brief Get the current timestamp as a formatted string.
 *
 * @return std::string Current time formatted as "YYYY/MM/DD hh:mm:ss" in UTC.
 */
std::string getCurrentTimestamp();

/**
 * @brief Get the current date as a string.
 *
 * @param separator Date separator (default: "/").
 * @return std::string Current date formatted as "YYYY{sep}MM{sep}DD".
 */
std::string getCurrentDate(const std::string& separator = "/");

/**
 * @brief Get a compact timestamp string (no separators).
 *
 * @param time The time value.
 * @param utc If true, use UTC; otherwise use local time.
 * @return std::string Formatted as "YYYYMMDDhhmmss".
 */
std::string getCompactTimestamp(const std::time_t& time, bool utc = true);

/**
 * @brief Get the current time in ISO 8601 format.
 *
 * @return std::string Formatted as "YYYY-MM-DDThh:mm:ss.mmmZ".
 */
std::string getCurrentISO8601();

/**
 * @brief Nanoseconds since the Unix epoch, read from std::chrono::system_clock.
 *
 * @return int64_t Nanoseconds since epoch (wall clock; not monotonic).
 */
int64_t systemEpochNanos() noexcept;

/**
 * @brief Process-wide clock whose values never repeat and never go back.
 *
 * Every call returns max(now, last + 1): the wall-clock time when it is strictly after the last value
 * handed out, the last value plus one nanosecond otherwise (same-nanosecond calls and clocks that step
 * backwards). The last value is published with a CAS loop, so any number of threads can call next()
 * concurrently and each receives a distinct value, in allocation order.
 */
class StrictlyIncreasingClock
{
public:
    /**
     * @brief Hand out the next value.
     *
     * @param now Current time in nanoseconds since epoch. Production uses the default (systemEpochNanos());
     *            tests pass a controlled value.
     * @return int64_t A value strictly greater than every value returned before, by this object.
     */
    int64_t next(int64_t now = systemEpochNanos()) noexcept;

private:
    std::atomic<int64_t> m_last {0}; ///< Last value handed out (0 = none yet).
};

/**
 * @brief The reception clock shared by every event-ingest thread of the process.
 *
 * @return StrictlyIncreasingClock& Function-local singleton.
 */
StrictlyIncreasingClock& receptionClock();

/**
 * @brief Format nanoseconds since epoch as ISO 8601 UTC with nanosecond precision.
 *
 * Reentrant (no gmtime). Negative values are handled by flooring to the previous second.
 *
 * @param nanos Nanoseconds since the Unix epoch.
 * @return std::string Formatted as "YYYY-MM-DDThh:mm:ss.nnnnnnnnnZ" (always nine fraction digits).
 */
std::string epochNanosToISO8601(int64_t nanos);

/**
 * @brief Convert a "YYYY/MM/DD hh:mm:ss" timestamp to ISO 8601 format.
 *
 * @param timestamp Input timestamp string.
 * @return std::string ISO 8601 string, or empty string on parse failure.
 */
std::string timestampToISO8601(const std::string& timestamp);

/**
 * @brief Convert a raw Unix epoch timestamp (as string) to ISO 8601 format.
 *
 * @param timestamp Epoch seconds as a string.
 * @return std::string ISO 8601 string, or empty string if input is invalid.
 */
std::string rawTimestampToISO8601(const std::string& timestamp);

/**
 * @brief Get seconds since Unix epoch as a duration.
 *
 * @return std::chrono::seconds Duration since epoch.
 */
std::chrono::seconds secondsSinceEpoch();

/**
 * @brief Get seconds since Unix epoch as an integer.
 *
 * @return int64_t Seconds since epoch.
 */
int64_t getSecondsFromEpoch();

} // namespace base::utils::time

#endif // _TIME_UTILS_HPP
