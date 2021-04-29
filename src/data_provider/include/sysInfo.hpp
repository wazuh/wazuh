/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYS_INFO_HPP
#define _SYS_INFO_HPP

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

#include "sysInfoInterface.h"

constexpr auto KByte{1024};

class EXPORTED SysInfo: public ISysInfo
{
public:
    SysInfo() = default;
    // LCOV_EXCL_START
    virtual ~SysInfo() = default;
    // LCOV_EXCL_STOP
    nlohmann::json hardware();
    nlohmann::json packages();
    nlohmann::json os();
    nlohmann::json processes();
    nlohmann::json networks();
    nlohmann::json ports();
private:
    virtual std::string getSerialNumber() const;
    virtual std::string getCpuName() const;
    virtual int getCpuMHz() const;
    virtual int getCpuCores() const;
    virtual void getMemory(nlohmann::json& info) const;
    virtual nlohmann::json getPackages() const;
    virtual nlohmann::json getOsInfo() const;
    virtual nlohmann::json getProcessesInfo() const;
    virtual nlohmann::json getNetworks() const;
    virtual nlohmann::json getPorts() const;
};

#endif //_SYS_INFO_HPP