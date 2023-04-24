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

using FullLogFunction = auto (*)(const char* log_level, const char* tag, const char* file, int line, const char* func, const char* msg, ...) -> void;

namespace Log
{

#define endl sourceFile {__FILE__, __LINE__, __func__}

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
            FullLogFunction m_logFunction;
            std::unordered_map<std::thread::id, std::string> m_threadsBuffers;
            std::string m_tag;

        protected:
            std::string m_logType;
            Logger() = default;

        public:
            ~Logger() = default;
            Logger& operator=(const Logger& other) = delete;
            Logger(const Logger& other) = delete;

            Logger& assignLogFunction(FullLogFunction& logFunction, const std::string& tag)
            {
                if (!m_logFunction)
                {
                    m_logFunction = logFunction;
                    m_tag = tag;
                }

                return *this;
            }

            // The << operator is overloaded to append data in the buffer for the current thread
            // but the message isn't logged until std::endl or Log::endl are found.
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
                    logObject.m_logFunction(logObject.m_logType.c_str(), logObject.m_tag.c_str(), __FILE__, __LINE__, __func__, logObject.m_threadsBuffers[threadId].c_str());
                    logObject.m_threadsBuffers.erase(threadId);
                }

                return logObject;
            }

            // This << overload is used when Log::endl is found. The file, line and function are taken from the sourceFile structure that
            // contains the required data.
            friend Logger& operator<<(Logger& logObject,
                                      sourceFile sourceLocation)
            {
                if (logObject.m_logFunction)
                {
                    std::lock_guard<std::mutex> lockGuard(logMutex);
                    auto threadId = std::this_thread::get_id();
                    logObject.m_logFunction(logObject.m_logType.c_str(), logObject.m_tag.c_str(), sourceLocation.file, sourceLocation.line, sourceLocation.func, logObject.m_threadsBuffers[threadId].c_str());
                    logObject.m_threadsBuffers.erase(threadId);
                }

                return logObject;
            }
    };

    class Info : public Logger
    {
        public:
            Info() : Logger()
            {
                m_logType = "info";
            };

            static Info& instance()
            {
                static Info logInstance;
                return logInstance;
            }
    };

    class Error : public Logger
    {
        public:
            Error() : Logger()
            {
                m_logType = "error";
            };

            static Error& instance()
            {
                static Error logInstance;
                return logInstance;
            }
    };

    class Debug : public Logger
    {
        public:
            Debug() : Logger()
            {
                m_logType = "debug";
            };

            static Debug& instance()
            {
                static Debug logInstance;
                return logInstance;
            }
    };

    class DebugVerbose : public Logger
    {
        public:
            DebugVerbose() : Logger()
            {
                m_logType = "debug_verbose";
            };

            static DebugVerbose& instance()
            {
                static DebugVerbose logInstance;
                return logInstance;
            }
    };

    class Warning : public Logger
    {
        public:
            Warning() : Logger()
            {
                m_logType = "warning";
            };

            static Warning& instance()
            {
                static Warning logInstance;
                return logInstance;
            }
    };

    static Info& info = Info::instance();
    static Error& error = Error::instance();
    static Debug& debug = Debug::instance();
    static DebugVerbose& debugVerbose = DebugVerbose::instance();
    static Warning& warning = Warning::instance();

} // namespace Log
#endif // LOGGER_HELPER_H
