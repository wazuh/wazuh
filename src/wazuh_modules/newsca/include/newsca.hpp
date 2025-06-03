/*
 * Wazuh NewSca
 * Copyright (C) 2015, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _NEWSCA_HPP
#define _NEWSCA_HPP
#include "commonDefs.h"
#include "dbsync.hpp"
#include "newsca.h"
#include "rsync.hpp"
#include "sysInfoInterface.h"
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

class EXPORTED NewSca final
{
public:
    static NewSca& instance()
    {
        static NewSca s_instance;
        return s_instance;
    }

    void init(const std::shared_ptr<ISysInfo>& spInfo,
              const std::function<void(const std::string&)> reportDiffFunction,
              const std::function<void(const std::string&)> reportSyncFunction,
              const std::function<void(const modules_log_level_t, const std::string&)> logFunction,
              const std::string& dbPath,
              const std::string& normalizerConfigPath,
              const std::string& normalizerType,
              const unsigned int inverval = 3600ul);

    void destroy();
    void push(const std::string& data);

private:
    NewSca();
    ~NewSca() = default;
    NewSca(const NewSca&) = delete;
    NewSca& operator=(const NewSca&) = delete;

    std::string getCreateStatement() const;

    void registerWithRsync();
    void updateChanges(const std::string& table, const nlohmann::json& values);
    void notifyChange(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table);
    void syncLoop(std::unique_lock<std::mutex>& lock);
    std::shared_ptr<ISysInfo> m_spInfo;
    std::function<void(const std::string&)> m_reportDiffFunction;
    std::function<void(const std::string&)> m_reportSyncFunction;
    std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;
    unsigned int m_intervalValue;
    bool m_stopping;
    std::unique_ptr<DBSync> m_spDBSync;
    std::unique_ptr<RemoteSync> m_spRsync;
    std::condition_variable m_cv;
    std::mutex m_mutex;
    std::string m_scanTime;
};

#endif //_NEWSCA_HPP
