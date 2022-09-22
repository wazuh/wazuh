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

using LogFunction = std::function<void(const std::string &)>;
static std::mutex logMutex;

namespace Log {

class Logger {
private:
  LogFunction m_logFunction;
  std::unordered_map<std::thread::id, std::string> m_threadsBuffers;

protected:
  Logger() = default;

public:
  ~Logger() = default;
  Logger &operator=(const Logger &other) = delete;
  Logger(const Logger &other) = delete;

  Logger &assignLogFunction(LogFunction &logFunction) {
    if (!m_logFunction) {
      m_logFunction = logFunction;
    }
    return *this;
  }

  friend Logger &operator<<(Logger &logObject, const std::string &msg) {
    if (!msg.empty()) {
      std::lock_guard<std::mutex> lockGuard(logMutex);
      logObject.m_threadsBuffers[std::this_thread::get_id()] += msg;
    }
    return logObject;
  }

  friend Logger &operator<<(Logger &logObject,
                            std::ostream &(*)(std::ostream &)) {
    if (logObject.m_logFunction) {
      std::lock_guard<std::mutex> lockGuard(logMutex);
      auto threadId = std::this_thread::get_id();
      logObject.m_logFunction(logObject.m_threadsBuffers[threadId]);
      logObject.m_threadsBuffers.erase(threadId);
    }
    return logObject;
  }
};

class Info : public Logger {
public:
  Info() : Logger(){};

  static Info &instance() {
    static Info logInstance;
    return logInstance;
  }
};

class Error : public Logger {
public:
  Error() : Logger(){};

  static Error &instance() {
    static Error logInstance;
    return logInstance;
  }
};

class Debug : public Logger {
public:
  Debug() : Logger(){};

  static Debug &instance() {
    static Debug logInstance;
    return logInstance;
  }
};

class DebugVerbose : public Logger {
public:
  DebugVerbose() : Logger(){};

  static DebugVerbose &instance() {
    static DebugVerbose logInstance;
    return logInstance;
  }
};

static Info &info = Info::instance();
static Error &error = Error::instance();
static Debug &debug = Debug::instance();
static DebugVerbose &debugVerbose = DebugVerbose::instance();

} // namespace Log
#endif // LOGGER_HELPER_H
