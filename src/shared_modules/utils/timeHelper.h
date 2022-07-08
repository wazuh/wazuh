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

#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static std::string getTimestamp(const std::time_t& time, const bool utc = true)
    {
        std::stringstream ss;
        // gmtime: result expressed as a UTC time
        tm* localTime { utc ? gmtime(&time) : localtime(&time)};
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
};

#pragma GCC diagnostic pop

#endif // _TIME_HELPER_H