/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo.hpp"
#include "sysInfo.h"
#include "cjsonSmartDeleter.hpp"

nlohmann::json SysInfo::hardware()
{
    return getHardware();
}

nlohmann::json SysInfo::packages()
{
    return getPackages();
}

nlohmann::json SysInfo::os()
{
    return getOsInfo();
}

nlohmann::json SysInfo::processes()
{
    return getProcessesInfo();
}

nlohmann::json SysInfo::networks()
{
    return getNetworks();
}

nlohmann::json SysInfo::ports()
{
    return getPorts();
}

void SysInfo::processes(std::function<void(nlohmann::json&)> callback)
{
    getProcessesInfo(callback);
}

void SysInfo::packages(std::function<void(nlohmann::json&)> callback)
{
    getPackages(callback);
}

nlohmann::json SysInfo::hotfixes()
{
    return getHotfixes();
}

nlohmann::json SysInfo::groups()
{
    return getGroups();
}

nlohmann::json SysInfo::users()
{
    return getUsers();
}

#ifdef __cplusplus
extern "C" {
#endif
int sysinfo_hardware(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& hw          {info.hardware()};
            *js_result = cJSON_Parse(hw.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}
int sysinfo_packages(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& packages    {info.packages()};
            *js_result = cJSON_Parse(packages.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}
int sysinfo_os(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& os          {info.os()};
            *js_result = cJSON_Parse(os.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}
int sysinfo_processes(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& processes   {info.processes()};
            *js_result = cJSON_Parse(processes.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}
int sysinfo_networks(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& networks    {info.networks()};
            *js_result = cJSON_Parse(networks.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}
int sysinfo_ports(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& ports       {info.ports()};
            *js_result = cJSON_Parse(ports.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}
void sysinfo_free_result(cJSON** js_data)
{
    if (*js_data)
    {
        cJSON_Delete(*js_data);
    }
}
int sysinfo_packages_cb(callback_data_t callback_data)
{
    auto retVal { -1 };

    try
    {
        if (callback_data.callback)
        {
            const auto callbackWrapper
            {
                [callback_data](nlohmann::json & jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback_data.callback(GENERIC, spJson.get(), callback_data.user_data);
                }
            };
            // LCOV_EXCL_START
            SysInfo info;
            // LCOV_EXCL_STOP
            info.packages(callbackWrapper);
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}

int sysinfo_processes_cb(callback_data_t callback_data)
{
    auto retVal { -1 };

    try
    {
        if (callback_data.callback)
        {
            const auto callbackWrapper
            {
                [callback_data](nlohmann::json & jsonResult)
                {
                    const std::unique_ptr<cJSON, CJsonSmartDeleter> spJson{ cJSON_Parse(jsonResult.dump().c_str()) };
                    callback_data.callback(GENERIC, spJson.get(), callback_data.user_data);
                }
            };
            // LCOV_EXCL_START
            SysInfo info;
            // LCOV_EXCL_STOP
            info.processes(callbackWrapper);
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}

int sysinfo_hotfixes(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& hotfixes       {info.hotfixes()};
            *js_result = cJSON_Parse(hotfixes.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}

int sysinfo_groups(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& grps       {info.groups()};
            *js_result = cJSON_Parse(grps.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}

int sysinfo_users(cJSON** js_result)
{
    auto retVal { -1 };

    try
    {
        if (js_result)
        {
            SysInfo info;
            const auto& users       {info.users()};
            *js_result = cJSON_Parse(users.dump().c_str());
            retVal = 0;
        }
    }
    // LCOV_EXCL_START
    catch (...)
    {}

    // LCOV_EXCL_STOP

    return retVal;
}

#ifdef __cplusplus
}
#endif
