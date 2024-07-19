/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "loggerHelper.h"
#include "gtest/gtest.h"

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

int main(int argc, char** argv)
{
    Log::assignLogFunction(
        [](const int logLevel,
           const std::string&,
           const std::string&,
           const int,
           const std::string&,
           const std::string& str,
           va_list args)
        {
            char formattedStr[MAXLEN] = {0};
            vsnprintf(formattedStr, MAXLEN, str.c_str(), args);

            if (logLevel == Log::LOGLEVEL_ERROR || logLevel == Log::LOGLEVEL_CRITICAL ||
                logLevel == Log::LOGLEVEL_WARNING)

            {
                std::cerr << formattedStr << "\n";
            }
            else
            {
                std::cout << formattedStr << "\n";
            }
        });

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
