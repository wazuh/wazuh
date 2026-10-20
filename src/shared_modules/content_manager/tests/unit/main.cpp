// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
/*
 * Wazuh - Content Merge Tool
 * Copyright (C) Wazuh Inc.
 *
 */

#include "gtest/gtest.h"
#include <cstdarg>
#include <functional>

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
