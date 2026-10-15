/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef LOGGER_HELPER_TEST_H
#define LOGGER_HELPER_TEST_H

#include "loggerHelper.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <thread>

void debugVerboseTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg);
void debugTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg);
void infoTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg);
void warningTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg);
void errorTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg);
void logFunctionWrapper(
    int level, const char* tag, const char* file, int line, const char* func, const char* msg, va_list args);
std::stringstream ssOutput;

class LoggerHelperTest : public ::testing::Test
{
protected:
    LoggerHelperTest() = default;
    virtual ~LoggerHelperTest() = default;

    static void SetUpTestSuite()
    {
        Log::assignLogFunction(
            [](const int logLevel,
               const char* tag,
               const char* file,
               const int line,
               const char* func,
               const char* logMessage,
               va_list args)
            { logFunctionWrapper(logLevel, tag, file, line, func, logMessage, args); });
    }

    virtual void SetUp()
    {
        ssOutput.str("");
    }
};
class LogFnTest : public ::testing::Test
{
protected:
    void SetUp() override { Log::setModuleLogFn(LogFn {}); }
    void TearDown() override { Log::setModuleLogFn(LogFn {}); }
};
#endif // LOGGER_HELPER_TEST_H
