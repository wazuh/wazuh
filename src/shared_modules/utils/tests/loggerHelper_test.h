/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 24, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LOGGER_HELPER_TEST_H
#define LOGGER_HELPER_TEST_H

#include "loggerHelper.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

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
               const std::string& tag,
               const std::string& file,
               const int line,
               const std::string& func,
               const std::string& logMessage,
               va_list args)
            { logFunctionWrapper(logLevel, tag.c_str(), file.c_str(), line, func.c_str(), logMessage.c_str(), args); });
    }

    virtual void SetUp()
    {
        ssOutput.str("");
    }
};
#endif // LOGGER_HELPER_TEST_H
