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

#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include "commonDefs.h"
#include <cstdarg>

// We can't use std::source_location until C++20
#define LogEndl Log::SourceFile {__FILE__, __LINE__, __func__}
#define logInfo(X, Y, ...) Log::Logger::info(X, LogEndl, Y, ##__VA_ARGS__)
#define logWarn(X, Y, ...) Log::Logger::warning(X, LogEndl, Y, ##__VA_ARGS__)
#define logDebug1(X, Y, ...) Log::Logger::debug(X, LogEndl, Y, ##__VA_ARGS__)
#define logDebug2(X, Y, ...) Log::Logger::debugVerbose(X, LogEndl, Y, ##__VA_ARGS__)
#define logError(X, Y, ...) Log::Logger::error(X, LogEndl, Y, ##__VA_ARGS__)
#define MAXLEN  65536

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

    static full_log_fnc_t globalLogFunction;

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-function"

    static void assignLogFunction(full_log_fnc_t logFunction)
    {
        globalLogFunction = logFunction;
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
                if (globalLogFunction)
                {
                    std::va_list args;
                    va_start(args, msg);
                    char formatted_str[MAXLEN];
                    vsnprintf(formatted_str, MAXLEN, msg, args);
                    va_end(args);

                    globalLogFunction(LOGLEVEL_INFO, tag, sourceFile.file, sourceFile.line, sourceFile.func, formatted_str);
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
                if (globalLogFunction)
                {
                    std::va_list args;
                    va_start(args, msg);
                    char formatted_str[MAXLEN];
                    vsnprintf(formatted_str, MAXLEN, msg, args);
                    va_end(args);

                    globalLogFunction(LOGLEVEL_WARNING, tag, sourceFile.file, sourceFile.line, sourceFile.func, formatted_str);
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
                if (globalLogFunction)
                {
                    std::va_list args;
                    va_start(args, msg);
                    char formatted_str[MAXLEN];
                    vsnprintf(formatted_str, MAXLEN, msg, args);
                    va_end(args);

                    globalLogFunction(LOGLEVEL_DEBUG, tag, sourceFile.file, sourceFile.line, sourceFile.func, formatted_str);
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
                if (globalLogFunction)
                {
                    std::va_list args;
                    va_start(args, msg);
                    char formatted_str[MAXLEN];
                    vsnprintf(formatted_str, MAXLEN, msg, args);
                    va_end(args);

                    globalLogFunction(LOGLEVEL_DEBUG_VERBOSE, tag, sourceFile.file, sourceFile.line, sourceFile.func, formatted_str);
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
                if (globalLogFunction)
                {
                    std::va_list args;
                    va_start(args, msg);
                    char formatted_str[MAXLEN];
                    vsnprintf(formatted_str, MAXLEN, msg, args);
                    va_end(args);

                    globalLogFunction(LOGLEVEL_ERROR, tag, sourceFile.file, sourceFile.line, sourceFile.func, formatted_str);
                }
            }
    };
} // namespace Log
#endif // LOGGER_HELPER_H
