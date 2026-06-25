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
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

auto constexpr LOGGER_DEFAULT_TAG {"logger-helper"};

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

inline std::string composeTag(std::string_view parentTag, std::string_view libName)
{
    if (parentTag.empty())
        return std::string(libName);
    auto open = parentTag.rfind("(");
    if (open != std::string_view::npos)
        return std::string(parentTag.substr(0, parentTag.size() - 1)) + "/" + std::string(libName) + ")";
    return std::string(parentTag) + "(" + std::string(libName) + ")";
}

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

    extern std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
#pragma GCC visibility pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

    /**
     * @brief Assign the global log function.
     *
     * @param logFunction callback function that is going to be called on every message logging operation.
     */
    static void assignLogFunction(
        const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
            logFunction)
    {
        if (!GLOBAL_LOG_FUNCTION)
        {
            GLOBAL_LOG_FUNCTION = logFunction;
        }
    }

    /**
     * @brief Deassign the global log function.
     *        Use it with care!
     *        Take into account that running it, you will disable the previous set logging functionality in the running
     *        executable.
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

                GLOBAL_LOG_FUNCTION(LOGLEVEL_INFO,
                                    tag ? tag : LOGGER_DEFAULT_TAG,
                                    sourceFile.file,
                                    sourceFile.line,
                                    sourceFile.func,
                                    msg,
                                    args);

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

                GLOBAL_LOG_FUNCTION(LOGLEVEL_WARNING,
                                    tag ? tag : LOGGER_DEFAULT_TAG,
                                    sourceFile.file,
                                    sourceFile.line,
                                    sourceFile.func,
                                    msg,
                                    args);

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

                GLOBAL_LOG_FUNCTION(LOGLEVEL_DEBUG,
                                    tag ? tag : LOGGER_DEFAULT_TAG,
                                    sourceFile.file,
                                    sourceFile.line,
                                    sourceFile.func,
                                    msg,
                                    args);

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

                GLOBAL_LOG_FUNCTION(LOGLEVEL_DEBUG_VERBOSE,
                                    tag ? tag : LOGGER_DEFAULT_TAG,
                                    sourceFile.file,
                                    sourceFile.line,
                                    sourceFile.func,
                                    msg,
                                    args);

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

                GLOBAL_LOG_FUNCTION(LOGLEVEL_ERROR,
                                    tag ? tag : LOGGER_DEFAULT_TAG,
                                    sourceFile.file,
                                    sourceFile.line,
                                    sourceFile.func,
                                    msg,
                                    args);

                va_end(args);
            }
        }
    };
} // namespace Log

/**
 * @brief Pre-bound log wrapper — stores a tag and calls GLOBAL_LOG_FUNCTION with it.
 *
 * Each component receives a LogFn from its caller and calls compose("myname") to
 * build its own LogFn. The tag shown in every log line is always
 * "<process>(<current-library>)" — only the library currently executing, not the
 * full call chain.
 *
 * Use the LOG_WARN / LOG_INFO / LOG_DEBUG1 / LOG_DEBUG2 / LOG_ERROR macros so that
 * __FILE__ / __LINE__ / __func__ are captured at the actual call site.
 */
struct LogFn
{
    std::string m_tag;

    LogFn() : m_tag(LOGGER_DEFAULT_TAG) {}
    LogFn(std::string_view tag) : m_tag(tag) {}  // NOLINT(google-explicit-constructor)
    LogFn(std::string tag) : m_tag(std::move(tag)) {}  // NOLINT(google-explicit-constructor)
    LogFn(const char* tag) : m_tag(tag ? tag : LOGGER_DEFAULT_TAG) {}  // NOLINT(google-explicit-constructor)

    /**
     * Returns a new LogFn for @p component within the same process.
     * Replaces the library part of the tag — does NOT accumulate a chain.
     *   LogFn{"proc"}.compose("rocksdb")          → "proc(rocksdb)"
     *   LogFn{"proc(keystore)"}.compose("rocksdb") → "proc(rocksdb)"
     */
    LogFn compose(std::string_view component) const
    {
        const auto open = m_tag.find('(');
        const auto base = (open != std::string::npos) ? m_tag.substr(0, open) : m_tag;
        if (base.empty())
            return LogFn {std::string(component)};
        return LogFn {base + "(" + std::string(component) + ")"};
    }

    const char* c_str() const { return m_tag.c_str(); }

    void info(Log::SourceFile src, const char* fmt, ...) const
    {
        if (Log::GLOBAL_LOG_FUNCTION)
        {
            std::va_list args;
            va_start(args, fmt);
            Log::GLOBAL_LOG_FUNCTION(Log::LOGLEVEL_INFO, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
            va_end(args);
        }
    }

    void warn(Log::SourceFile src, const char* fmt, ...) const
    {
        if (Log::GLOBAL_LOG_FUNCTION)
        {
            std::va_list args;
            va_start(args, fmt);
            Log::GLOBAL_LOG_FUNCTION(Log::LOGLEVEL_WARNING, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
            va_end(args);
        }
    }

    void debug1(Log::SourceFile src, const char* fmt, ...) const
    {
        if (Log::GLOBAL_LOG_FUNCTION)
        {
            std::va_list args;
            va_start(args, fmt);
            Log::GLOBAL_LOG_FUNCTION(Log::LOGLEVEL_DEBUG, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
            va_end(args);
        }
    }

    void debug2(Log::SourceFile src, const char* fmt, ...) const
    {
        if (Log::GLOBAL_LOG_FUNCTION)
        {
            std::va_list args;
            va_start(args, fmt);
            Log::GLOBAL_LOG_FUNCTION(
                Log::LOGLEVEL_DEBUG_VERBOSE, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
            va_end(args);
        }
    }

    void error(Log::SourceFile src, const char* fmt, ...) const
    {
        if (Log::GLOBAL_LOG_FUNCTION)
        {
            std::va_list args;
            va_start(args, fmt);
            Log::GLOBAL_LOG_FUNCTION(Log::LOGLEVEL_ERROR, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
            va_end(args);
        }
    }
};

// clang-format off
#define LOG_INFO(fn, fmt, ...)   (fn).info( {__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__)
#define LOG_WARN(fn, fmt, ...)   (fn).warn( {__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__)
#define LOG_DEBUG1(fn, fmt, ...) (fn).debug1({__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__)
#define LOG_DEBUG2(fn, fmt, ...) (fn).debug2({__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fn, fmt, ...)  (fn).error( {__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__)
// clang-format on

#endif // LOGGER_HELPER_H
