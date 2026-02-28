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

#ifndef _TIME_UTILS_HPP
#define _TIME_UTILS_HPP

#include <chrono>
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
