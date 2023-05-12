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

#include "loggerHelper.h"
#include "loggerHelper_test.h"
#include <sstream>
#include <regex>
#include <chrono>

constexpr auto INFO_REGEX = "info Tag .+\\.cpp \\d+ TestBody Testing Info log\\n";
constexpr auto ERROR_REGEX = "error Tag .+\\.cpp \\d+ TestBody Testing Error log\\n";
constexpr auto DEBUG_REGEX = "debug Tag .+\\.cpp \\d+ TestBody Testing Debug log\\n";
constexpr auto DEBUG_VERBOSE_REGEX = "debug_verbose Tag .+\\.cpp \\d+ TestBody Testing Debug Verbose log\\n";
constexpr auto WARNING_REGEX = "warning Tag .+\\.cpp \\d+ TestBody Testing Warning log\\n";

constexpr auto INFO_REGEX_STDENDL = "info Tag .+\\.h \\d+ operator<< Testing Info log\\n";
constexpr auto ERROR_REGEX_STDENDL = "error Tag .+\\.h \\d+ operator<< Testing Error log\\n";
constexpr auto DEBUG_REGEX_STDENDL = "debug Tag .+\\.h \\d+ operator<< Testing Debug log\\n";
constexpr auto DEBUG_VERBOSE_REGEX_STDENDL = "debug_verbose Tag .+\\.h \\d+ operator<< Testing Debug Verbose log\\n";
constexpr auto WARNING_REGEX_STDENDL = "warning Tag .+\\.h \\d+ operator<< Testing Warning log\\n";

constexpr auto INFO_REGEX_THREAD = "info Tag .+\\.cpp \\d+ operator\\(\\) Testing Info log";
constexpr auto ERROR_REGEX_THREAD = "error Tag .+\\.cpp \\d+ operator\\(\\) Testing Error log";
constexpr auto DEBUG_REGEX_THREAD = "debug Tag .+\\.cpp \\d+ operator\\(\\) Testing Debug log";
constexpr auto DEBUG_VERBOSE_REGEX_THREAD = "debug_verbose Tag .+\\.cpp \\d+ operator\\(\\) Testing Debug Verbose log";
constexpr auto WARNING_REGEX_THREAD = "warning Tag .+\\.cpp \\d+ operator\\(\\) Testing Warning log";

void debugVerboseTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...)
{
    ssOutput << "debug_verbose" << " " << tag << " " << file << " " << line << " " << func << " " << msg << std::endl;
}

void debugTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...)
{
    ssOutput << "debug" << " " << tag << " " << file << " " << line << " " << func << " " << msg << std::endl;
}

void infoTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...)
{
    ssOutput << "info" << " " << tag << " " << file << " " << line << " " << func << " " << msg << std::endl;
}

void warningTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...)
{
    ssOutput << "warning" << " " << tag << " " << file << " " << line << " " << func << " " << msg << std::endl;
}

void errorTestFunction(const char* tag, const char* file, int line, const char* func, const char* msg, ...)
{
    ssOutput << "error" << " " << tag << " " << file << " " << line << " " << func << " " << msg << std::endl;
}

TEST_F(LoggerHelperTest, simpleInfoTest)
{
    Log::info << "Testing Info log" << LogEndl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(INFO_REGEX)));
}

TEST_F(LoggerHelperTest, simpleInfoTestWithStdEndl)
{
    Log::info << "Testing Info log" << std::endl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(INFO_REGEX_STDENDL)));
}

TEST_F(LoggerHelperTest, simpleErrorTest)
{
    Log::error << "Testing Error log" << LogEndl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(ERROR_REGEX)));
}

TEST_F(LoggerHelperTest, simpleErrorTestWithStdEndl)
{
    Log::error << "Testing Error log" << std::endl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(ERROR_REGEX_STDENDL)));
}

TEST_F(LoggerHelperTest, simpleDebugTest)
{
    Log::debug << "Testing Debug log" << LogEndl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(DEBUG_REGEX)));
}

TEST_F(LoggerHelperTest, simpleDebugTestWithStdEndl)
{
    Log::debug << "Testing Debug log" << std::endl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(DEBUG_REGEX_STDENDL)));
}

TEST_F(LoggerHelperTest, simpleDebugVerboseTest)
{
    Log::debugVerbose << "Testing Debug Verbose log" << LogEndl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(DEBUG_VERBOSE_REGEX)));
}

TEST_F(LoggerHelperTest, simpleDebugVerboseTestWithStdEndl)
{
    Log::debugVerbose << "Testing Debug Verbose log" << std::endl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(DEBUG_VERBOSE_REGEX_STDENDL)));
}

TEST_F(LoggerHelperTest, simpleWarningTest)
{
    Log::warning << "Testing Warning log" << LogEndl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(WARNING_REGEX)));
}

TEST_F(LoggerHelperTest, simpleWarningTestWithStdEndl)
{
    Log::warning << "Testing Warning log" << std::endl;
    EXPECT_TRUE(std::regex_match(ssOutput.str(), std::regex(WARNING_REGEX_STDENDL)));
}

TEST_F(LoggerHelperTest, multiThreadTest)
{
    std::thread t1([]()
    {
        for (int i = 0; i < 10; i++)
        {
            Log::info << "Testing Info log" << LogEndl;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });
    std::thread t2([]()
    {
        for (int i = 0; i < 10; i++)
        {
            Log::error << "Testing Error log" << LogEndl;
            std::this_thread::sleep_for(std::chrono::milliseconds(4));
        }
    });
    std::thread t3([]()
    {
        for (int i = 0; i < 10; i++)
        {
            Log::debug << "Testing Debug log" << LogEndl;
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
        }
    });
    std::thread t4([]()
    {
        for (int i = 0; i < 10; i++)
        {
            Log::debugVerbose << "Testing Debug Verbose log" << LogEndl;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    });
    std::thread t5([]()
    {
        for (int i = 0; i < 10; i++)
        {
            Log::warning << "Testing Warning log" << LogEndl;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });
    t1.join();
    t2.join();
    t3.join();
    t4.join();
    t5.join();

    // We make sure that all lines are valid
    std::string newLine;

    while (std::getline(ssOutput, newLine))
    {
        if (! (std::regex_match(newLine, std::regex(INFO_REGEX_THREAD)) ||
                std::regex_match(newLine, std::regex(ERROR_REGEX_THREAD)) ||
                std::regex_match(newLine, std::regex(DEBUG_REGEX_THREAD)) ||
                std::regex_match(newLine, std::regex(DEBUG_VERBOSE_REGEX_THREAD)) ||
                std::regex_match(newLine, std::regex(WARNING_REGEX_THREAD))) )
        {
            FAIL() << "Invalid line: " << newLine;
        }
    }

    SUCCEED();
}
