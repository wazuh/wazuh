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

// We can't use std::source_location until C++20
#define LogEndl Log::SourceFile {__FILE__, __LINE__, __func__}
#define logInfo(X, Y) Log::Logger::info(X, Y, LogEndl)
#define logWarn(X, Y) Log::Logger::warning(X, Y, LogEndl)
#define logDebug1(X, Y) Log::Logger::debug(X, Y, LogEndl)
#define logDebug2(X, Y) Log::Logger::debugVerbose(X, Y, LogEndl)
#define logError(X, Y) Log::Logger::error(X, Y, LogEndl)

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
            static void info(const std::string& tag, const std::string& msg, SourceFile sourceFile)
            {
                if (globalLogFunction)
                {
                    globalLogFunction(LOGLEVEL_INFO, tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
                }
            }

            /**
             * @brief WARNING LOG.
             *
             * @param tag Module tag.
             * @param msg Message to be logged.
             * @param sourceFile Log location.
             */
            static void warning(const std::string& tag, const std::string& msg, SourceFile sourceFile)
            {
                if (globalLogFunction)
                {
                    globalLogFunction(LOGLEVEL_WARNING, tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
                }
            }

            /**
             * @brief DEBUG log.
             *
             * @param tag Module tag.
             * @param msg Message to be logged.
             * @param sourceFile Log location.
             */
            static void debug(const std::string& tag, const std::string& msg, SourceFile sourceFile)
            {
                if (globalLogFunction)
                {
                    globalLogFunction(LOGLEVEL_DEBUG, tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
                }
            }

            /**
             * @brief DEBUG VERBOSE log.
             *
             * @param tag Module tag.
             * @param msg Message to be logged.
             * @param sourceFile Log location.
             */
            static void debugVerbose(const std::string& tag, const std::string& msg, SourceFile sourceFile)
            {
                if (globalLogFunction)
                {
                    globalLogFunction(LOGLEVEL_DEBUG_VERBOSE, tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
                }
            }

            /**
             * @brief ERROR log.
             *
             * @param tag Module tag.
             * @param msg Message to be logged.
             * @param sourceFile Log location.
             */
            static void error(const std::string& tag, const std::string& msg, SourceFile sourceFile)
            {
                if (globalLogFunction)
                {
                    globalLogFunction(LOGLEVEL_ERROR, tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
                }
            }
    };
} // namespace Log
#endif // LOGGER_HELPER_H
