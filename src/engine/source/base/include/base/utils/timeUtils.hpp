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

std::string getTimestamp(const time_t& time, bool utc = true);
std::string getCurrentTimestamp();
std::string getCurrentDate(const std::string& separator = "/");
std::string getCompactTimestamp(const std::time_t& time, bool utc = true);
std::string getCurrentISO8601();
std::string timestampToISO8601(const std::string& timestamp);
std::string rawTimestampToISO8601(const std::string& timestamp);
std::chrono::seconds secondsSinceEpoch();
int64_t getSecondsFromEpoch();

} // namespace base::utils::time

#endif // _TIME_UTILS_HPP
