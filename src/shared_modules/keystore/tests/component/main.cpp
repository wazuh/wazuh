/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "loggerHelper.h"
#include "gtest/gtest.h"

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
