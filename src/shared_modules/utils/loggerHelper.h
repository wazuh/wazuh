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
// clang-format off
// Macros for Log::LogFn instances. Debug variants skip argument evaluation when debug is inactive.
#define LOGFN_INFO(fn, fmt, ...)   do { if (Log::isInfoEnabled())   { (fn).info(  {__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__); } } while (0)
#define LOGFN_WARN(fn, fmt, ...)   do { if (Log::isWarnEnabled())   { (fn).warn(  {__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__); } } while (0)
#define LOGFN_DEBUG1(fn, fmt, ...) do { if (Log::isDebugEnabled())  { (fn).debug1({__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__); } } while (0)
#define LOGFN_DEBUG2(fn, fmt, ...) do { if (Log::isDebug2Enabled()) { (fn).debug2({__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__); } } while (0)
#define LOGFN_ERROR(fn, fmt, ...)  do { if (Log::isErrorEnabled())  { (fn).error( {__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__); } } while (0)
// CRITICAL is unfiltered by design (no isCriticalEnabled() gate): the shared C/C++ logging
// bridge every module wires in as its log callback (mtLoggingFunctionsWrapper,
// shared/src/debug_op.c -- used by https_client, remoted_module, inventory_sync_server,
// vulnerability_scanner and content_manager alike) logs then exit(1)s on this level, the exact
// same log-then-exit(1) sequence as _merror_exit()/_mlerror_exit() (shared/src/debug_op.c), for
// a config that can never work as given (mirrors client-agent/src/main.c's own hard exit on a
// missing/invalid <server><address>). It must never be silently dropped.
#define LOGFN_CRITICAL(fn, fmt, ...) do { (fn).critical({__FILE__, __LINE__, __func__}, fmt, ##__VA_ARGS__); } while (0)
// clang-format on

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
// Hidden visibility for everything below: GLOBAL_LOG_FUNCTION/GLOBAL_LOG_LEVEL must stay
// private to each DSO, and so must every inline function/class that reads them --
// otherwise the dynamic linker interposes same-named inline symbols across shared
// objects (e.g. two .so's both defining isLevelEnabled()) and calls from one DSO can
// end up executing another DSO's copy, silently reading *its* empty/unset globals.
#pragma GCC visibility push(hidden)

    extern std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;

    // Minimum level for LOGFN_* filtering. inline so each DSO gets its own copy.
    inline int GLOBAL_LOG_LEVEL {LOGLEVEL_DEBUG};

    inline bool isLevelEnabled(int level) noexcept
    {
        return GLOBAL_LOG_FUNCTION && level >= GLOBAL_LOG_LEVEL;
    }

    // Per-level helpers used by LOGFN_* macros. Defined inside the namespace so that
    // LOGLEVEL_* identifiers resolve correctly whether or not defs.h is included.
    inline bool isInfoEnabled() noexcept
    {
        return isLevelEnabled(LOGLEVEL_INFO);
    }
    inline bool isWarnEnabled() noexcept
    {
        return isLevelEnabled(LOGLEVEL_WARNING);
    }
    inline bool isDebugEnabled() noexcept
    {
        return isLevelEnabled(LOGLEVEL_DEBUG);
    }
    inline bool isDebug2Enabled() noexcept
    {
        return isLevelEnabled(LOGLEVEL_DEBUG_VERBOSE);
    }
    inline bool isErrorEnabled() noexcept
    {
        return isLevelEnabled(LOGLEVEL_ERROR);
    }

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

    /** Sets the minimum log level. LOGFN_* macros skip messages below this level. */
    static void setLogLevel(int level)
    {
        GLOBAL_LOG_LEVEL = level;
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
    // Pre-bound log wrapper. Holds a tag string and dispatches through GLOBAL_LOG_FUNCTION.
    // Use via LOGFN_* macros so that source location is captured at the call site.
    //
    // The type keeps default visibility even though the surrounding block is hidden: LogFn is
    // embedded as a member (m_logFn) in default-visibility classes (TRocksDBWrapper, dispatchers,
    // ...) that are ODR-merged across shared objects. A hidden member type in a visible, merged
    // class is an ODR/ABI mismatch that corrupts m_tag. The dispatch methods below stay hidden so
    // each DSO still reads its own GLOBAL_LOG_FUNCTION (see the block comment above).
    struct __attribute__((visibility("default"))) LogFn
    {
        std::string m_tag;

        LogFn()
            : m_tag(LOGGER_DEFAULT_TAG)
        {
        }
        LogFn(std::string_view tag)
            : m_tag(tag)
        {
        } // NOLINT(google-explicit-constructor)
        LogFn(std::string tag)
            : m_tag(std::move(tag))
        {
        } // NOLINT(google-explicit-constructor)
        LogFn(const char* tag)
            : m_tag(tag ? tag : LOGGER_DEFAULT_TAG)
        {
        } // NOLINT(google-explicit-constructor)

        // Returns a new LogFn with the library part of the tag replaced by component.
        LogFn compose(std::string_view component) const
        {
            const auto open = m_tag.find('(');
            const auto base = (open != std::string::npos) ? m_tag.substr(0, open) : m_tag;
            if (base.empty())
                return LogFn {std::string(component)};
            return LogFn {base + "(" + std::string(component) + ")"};
        }

        const char* c_str() const
        {
            return m_tag.c_str();
        }

        __attribute__((visibility("hidden"))) void info(SourceFile src, const char* fmt, ...) const
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, fmt);
                GLOBAL_LOG_FUNCTION(LOGLEVEL_INFO, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
                va_end(args);
            }
        }

        __attribute__((visibility("hidden"))) void warn(SourceFile src, const char* fmt, ...) const
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, fmt);
                GLOBAL_LOG_FUNCTION(LOGLEVEL_WARNING, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
                va_end(args);
            }
        }

        __attribute__((visibility("hidden"))) void debug1(SourceFile src, const char* fmt, ...) const
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, fmt);
                GLOBAL_LOG_FUNCTION(LOGLEVEL_DEBUG, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
                va_end(args);
            }
        }

        __attribute__((visibility("hidden"))) void debug2(SourceFile src, const char* fmt, ...) const
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, fmt);
                GLOBAL_LOG_FUNCTION(LOGLEVEL_DEBUG_VERBOSE, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
                va_end(args);
            }
        }

        __attribute__((visibility("hidden"))) void error(SourceFile src, const char* fmt, ...) const
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, fmt);
                GLOBAL_LOG_FUNCTION(LOGLEVEL_ERROR, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
                va_end(args);
            }
        }

        // Unrecoverable misconfiguration: the caller's log callback is expected to terminate
        // the process on this level (see mtLoggingFunctionsWrapper). Not level-filtered.
        __attribute__((visibility("hidden"))) void critical(SourceFile src, const char* fmt, ...) const
        {
            if (GLOBAL_LOG_FUNCTION)
            {
                std::va_list args;
                va_start(args, fmt);
                GLOBAL_LOG_FUNCTION(LOGLEVEL_CRITICAL, m_tag.c_str(), src.file, src.line, src.func, fmt, args);
                va_end(args);
            }
        }
    }; // struct LogFn

    // Returns the thread-local LogFn for the current module context.
    inline LogFn& currentModuleLogFn()
    {
        thread_local LogFn tl_logFn;
        return tl_logFn;
    }

    // Sets the module LogFn for the calling thread.
    inline void setModuleLogFn(LogFn fn)
    {
        currentModuleLogFn() = std::move(fn);
    }

    // RAII guard that installs a LogFn on the calling thread and restores the previous one on destruction.
    class ScopedModuleLogFn
    {
        LogFn m_saved;

    public:
        explicit ScopedModuleLogFn(LogFn fn)
            : m_saved(currentModuleLogFn())
        {
            setModuleLogFn(std::move(fn));
        }
        ~ScopedModuleLogFn()
        {
            setModuleLogFn(std::move(m_saved));
        }
        ScopedModuleLogFn(const ScopedModuleLogFn&) = delete;
        ScopedModuleLogFn& operator=(const ScopedModuleLogFn&) = delete;
    };
    // Returns a LogFn with the library name composed onto the calling thread's module LogFn.
    inline LogFn makeLibLogFn(std::string_view libName)
    {
        return currentModuleLogFn().compose(libName);
    }
#pragma GCC visibility pop
} // namespace Log

using LogFn = Log::LogFn;
using Log::makeLibLogFn;

#endif // LOGGER_HELPER_H
