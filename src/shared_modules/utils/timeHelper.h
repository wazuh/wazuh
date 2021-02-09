/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static std::string getTimestamp(std::time_t time)
    {
        std::string timestamp;
        tm* localTime { localtime(&time) };
        // Final timestamp: "YYYY/MM/DD h:m:s"
        timestamp  = std::to_string(localTime->tm_year + 1900);
        timestamp += "/";
        timestamp += std::to_string(localTime->tm_mon + 1);
        timestamp += "/";
        timestamp += std::to_string(localTime->tm_mday);
        timestamp += " ";
        timestamp += std::to_string(localTime->tm_hour);
        timestamp += ":";
        timestamp += std::to_string(localTime->tm_min);
        timestamp += ":";
        timestamp += std::to_string(localTime->tm_sec);
        return timestamp;
    }

    static std::string getCurrentTimestamp()
    {
        return getTimestamp(std::time(nullptr));
    }
};

#endif // _TIME_HELPER_H