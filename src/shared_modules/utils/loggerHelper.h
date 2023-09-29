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
#define LogEndl Log::sourceFile {__FILE__, __LINE__, __func__}

namespace Log
{
    static std::mutex logMutex;
    struct sourceFile
    {
        const char* file;
        int line;
        const char* func;
    };

    class Logger
    {
        private:
            full_log_fnc_t m_logFunction;
            std::unordered_map<std::thread::id, std::string> m_threadsBuffers;
            std::string m_tag;

        protected:
            Logger()
            {
                m_logFunction = nullptr;
            }

        public:
            ~Logger() = default;
            Logger& operator=(const Logger& other) = delete;
            Logger(const Logger& other) = delete;

            Logger& assignLogFunction(full_log_fnc_t logFunction, const std::string& tag)
            {
                if (!m_logFunction && logFunction)
                {
                    m_logFunction = logFunction;
                    m_tag = tag;
                }

                return *this;
            }

            // The << operator is overloaded to append data in the buffer for the current thread
            // but the message isn't logged until std::endl or LogEndl are found.
            friend Logger& operator<<(Logger& logObject, const std::string& msg)
            {
                if (!msg.empty())
                {
                    std::lock_guard<std::mutex> lockGuard(logMutex);
                    logObject.m_threadsBuffers[std::this_thread::get_id()] += msg;
                }

                return logObject;
            }

            // This << overload is used when std::endl is found. But the file, line and function always point here.
            friend Logger& operator<<(Logger& logObject,
                                      std::ostream & (*)(std::ostream&))
            {
                if (logObject.m_logFunction)
                {
                    std::lock_guard<std::mutex> lockGuard(logMutex);
                    auto threadId = std::this_thread::get_id();
                    logObject.m_logFunction(logObject.m_tag.c_str(), __FILE__, __LINE__, __func__, logObject.m_threadsBuffers[threadId].c_str());
                    logObject.m_threadsBuffers.erase(threadId);
                }

                return logObject;
            }

            // This << overload is used when LogEndl is found. The file, line and function are taken from the sourceFile structure that
            // contains the required data.
            friend Logger& operator<<(Logger& logObject,
                                      sourceFile sourceLocation)
            {
                if (logObject.m_logFunction)
                {
                    std::lock_guard<std::mutex> lockGuard(logMutex);
                    auto threadId = std::this_thread::get_id();
                    logObject.m_logFunction(logObject.m_tag.c_str(), sourceLocation.file, sourceLocation.line, sourceLocation.func, logObject.m_threadsBuffers[threadId].c_str());
                    logObject.m_threadsBuffers.erase(threadId);
                }

                return logObject;
            }
    };

    class DebugVerbose : public Logger
    {
        public:
            static DebugVerbose& instance()
            {
                static DebugVerbose logInstance;
                return logInstance;
            }
    };

    class Debug : public Logger
    {
        public:
            static Debug& instance()
            {
                static Debug logInstance;
                return logInstance;
            }
    };

    class Info : public Logger
    {
        public:
            static Info& instance()
            {
                static Info logInstance;
                return logInstance;
            }
    };

    class Warning : public Logger
    {
        public:
            static Warning& instance()
            {
                static Warning logInstance;
                return logInstance;
            }
    };

    class Error : public Logger
    {
        public:
            static Error& instance()
            {
                static Error logInstance;
                return logInstance;
            }
    };

    static DebugVerbose& debugVerbose = DebugVerbose::instance();
    static Debug& debug = Debug::instance();
    static Info& info = Info::instance();
    static Warning& warning = Warning::instance();
    static Error& error = Error::instance();

} // namespace Log
#endif // LOGGER_HELPER_H
