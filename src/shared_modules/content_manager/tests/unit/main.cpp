/*
 * Wazuh - Content Merge Tool
 * Copyright (C) 2015, Wazuh Inc.
 * January 10, 2023.
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
