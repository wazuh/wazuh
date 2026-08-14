/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdarg>
#include <functional>

namespace Log
{
    // Per-binary definition of loggerHelper.h's hidden DSO-global log sink.
    // libhttps_client exports its own copy hidden, so the test executable must
    // define its own (mirrors hcInterface.cpp).
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
    GLOBAL_LOG_FUNCTION;
} // namespace Log

int main(int argc, char** argv)
{
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}
