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
#include "../../headers/logging_helper.h"

// We can't use std::source_location until C++20
#define LogEndl Log::SourceFile {__FILE__, __LINE__, __func__}
#define logInfo(X, Y) Log::Logger::info(X, Y, LogEndl)
#define logWarn(X, Y) Log::Logger::warning(X, Y, LogEndl)
#define logDebug1(X, Y) Log::Logger::debug(X, Y, LogEndl)
#define logDebug2(X, Y) Log::Logger::debugVerbose(X, Y, LogEndl)
#define logError(X, Y) Log::Logger::error(X, Y, LogEndl)

#define VS_WM_NAME         "vulnerability-scanner"
#define WM_VULNSCAN_LOGTAG "wazuh-modulesd:" VS_WM_NAME

typedef full_log_fnc_t (*log_functions_t) (modules_log_level_t level);

namespace Log
{
    struct SourceFile
    {
        const char* file;
        int line;
        const char* func;
    };

    //static std::unordered_map<LOG_LEVEL, full_log_fnc_t> m_logFunctions = {};
    static log_functions_t globalLogFunctions = {};

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-function"

    static void assignLogFunction(log_functions_t logFunctions)
    {
        globalLogFunctions = logFunctions;
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
                full_log_fnc_t info = globalLogFunctions(modules_log_level_t::LOG_INFO);
                if (info)
                {
                    info(tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
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
                full_log_fnc_t warn = globalLogFunctions(modules_log_level_t::LOG_WARNING);
                if (warn)
                {
                    warn(tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
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
                full_log_fnc_t debug = globalLogFunctions(modules_log_level_t::LOG_DEBUG);
                if (debug)
                {
                    debug(tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
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
                full_log_fnc_t debug = globalLogFunctions(modules_log_level_t::LOG_DEBUG_VERBOSE);
                if (debug)
                {
                    debug(tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
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
                full_log_fnc_t error = globalLogFunctions(modules_log_level_t::LOG_ERROR);
                if (error)
                {
                    error(tag.c_str(), sourceFile.file, sourceFile.line, sourceFile.func, msg.c_str());
                }
            }
    };
} // namespace Log
#endif // LOGGER_HELPER_H
