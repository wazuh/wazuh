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
#include "gtest/gtest.h"
#include "gmock/gmock.h"

void debugVerboseTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...);
void debugTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...);
void infoTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...);
void warningTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...);
void errorTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...);
std::stringstream ssOutput;

class LoggerHelperTest : public ::testing::Test
{
    protected:
        LoggerHelperTest() = default;
        virtual ~LoggerHelperTest() = default;

        static void SetUpTestSuite()
        {
            Log::debugVerbose.assignLogFunction(debugVerboseTestFunction, "Tag");
            Log::debug.assignLogFunction(debugTestFunction, "Tag");
            Log::info.assignLogFunction(infoTestFunction, "Tag");
            Log::warning.assignLogFunction(warningTestFunction, "Tag");
            Log::error.assignLogFunction(errorTestFunction, "Tag");
        }

        virtual void SetUp()
        {
            ssOutput.str("");
        }
};
#endif //LOGGER_HELPER_TEST_H
