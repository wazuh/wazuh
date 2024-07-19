/*
 * Wazuh logging helper
 * Copyright (C) 2015, Wazuh Inc.
 * September 15, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LOGGER_HELPER_H
#define LOGGER_HELPER_H

#include "commonDefs.h"
#include <cstdarg>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

// We can't use std::source_location until C++20
#define LogEndl                                                                                                        \
    Log::SourceFile                                                                                                    \
    {                                                                                                                  \
        __FILE__, __LINE__, __func__                                                                                   \
    }
#define logInfo(X, Y, ...)   Log::Logger::info(X, LogEndl, Y, ##__VA_ARGS__)
#define logWarn(X, Y, ...)   Log::Logger::warning(X, LogEndl, Y, ##__VA_ARGS__)
#define logDebug1(X, Y, ...) Log::Logger::debug(X, LogEndl, Y, ##__VA_ARGS__)
#define logDebug2(X, Y, ...) Log::Logger::debugVerbose(X, LogEndl, Y, ##__VA_ARGS__)
#define logError(X, Y, ...)  Log::Logger::error(X, LogEndl, Y, ##__VA_ARGS__)
constexpr auto MAXLEN {65536};

namespace Log
{
    auto constexpr LOGLEVEL_DEBUG_VERBOSE {5};
    auto constexpr LOGLEVEL_CRITICAL {4};
    auto constexpr LOGLEVEL_ERROR {3};
    auto constexpr LOGLEVEL_WARNING {2};
    auto constexpr LOGLEVEL_INFO {1};
    auto constexpr LOGLEVEL_DEBUG {0};

    struct SourceFile
    {
        const char* file;
        int line;
        const char* func;
    };
// Remove visibility of this extern function
#pragma GCC visibility push(hidden)

    extern std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
#pragma GCC visibility pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

    /**
     * @brief Assign the global log function.
     *        
     * @param logFunction callback function that is going to be called on every message logging operation.
     */
    static void assignLogFunction(const std::function<void(const int,
                                                           const std::string&,
                                                           const std::string&,
                                                           const int,
                                                           const std::string&,
                                                           const std::string&,
                                                           va_list)>& logFunction)
    {
        if (!GLOBAL_LOG_FUNCTION)
        {
            GLOBAL_LOG_FUNCTION = logFunction;
        }
    }

    /**
     * @brief Deassign the global log function.
     *        Use it with care!
     *        Take into account that running it, you will disable the previous set logging functionality in the running executable.
     *
     */
    static void deassignLogFunction()
    {
        GLOBAL_LOG_FUNCTION = nullptr;
    }
    
#pragma GCC diagnostic pop

    /**
     * @brief Logging helper class.
     *
     */
    class Logger final
    {
    public:
        /**
         * @brief INFO log.
         *
         * @param tag Module tag.
         * @param msg Message to be logged.
         * @param sourceFile Log location.
         */
        static void info(const char* tag, SourceFile sourceFile, const char* msg, ...)
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, msg);

                GLOBAL_LOG_FUNCTION(LOGLEVEL_INFO, tag, sourceFile.file, sourceFile.line, sourceFile.func, msg, args);

                va_end(args);
            }
        }

        /**
         * @brief WARNING LOG.
         *
         * @param tag Module tag.
         * @param msg Message to be logged.
         * @param sourceFile Log location.
         */
        static void warning(const char* tag, SourceFile sourceFile, const char* msg, ...)
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, msg);

                GLOBAL_LOG_FUNCTION(
                    LOGLEVEL_WARNING, tag, sourceFile.file, sourceFile.line, sourceFile.func, msg, args);

                va_end(args);
            }
        }

        /**
         * @brief DEBUG log.
         *
         * @param tag Module tag.
         * @param msg Message to be logged.
         * @param sourceFile Log location.
         */
        static void debug(const char* tag, SourceFile sourceFile, const char* msg, ...)
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, msg);

                GLOBAL_LOG_FUNCTION(LOGLEVEL_DEBUG, tag, sourceFile.file, sourceFile.line, sourceFile.func, msg, args);

                va_end(args);
            }
        }

        /**
         * @brief DEBUG VERBOSE log.
         *
         * @param tag Module tag.
         * @param msg Message to be logged.
         * @param sourceFile Log location.
         */
        static void debugVerbose(const char* tag, SourceFile sourceFile, const char* msg, ...)
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, msg);

                GLOBAL_LOG_FUNCTION(
                    LOGLEVEL_DEBUG_VERBOSE, tag, sourceFile.file, sourceFile.line, sourceFile.func, msg, args);

                va_end(args);
            }
        }

        /**
         * @brief ERROR log.
         *
         * @param tag Module tag.
         * @param msg Message to be logged.
         * @param sourceFile Log location.
         */
        static void error(const char* tag, SourceFile sourceFile, const char* msg, ...)
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, msg);

                GLOBAL_LOG_FUNCTION(LOGLEVEL_ERROR, tag, sourceFile.file, sourceFile.line, sourceFile.func, msg, args);

                va_end(args);
            }
        }
    };
} // namespace Log
#endif // LOGGER_HELPER_H
