/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo.hpp"
#include "sysInfo.h"

nlohmann::json SysInfo::hardware()
{
    nlohmann::json ret;
    ret["board_serial"] = getSerialNumber();
    ret["cpu_name"] = getCpuName();
    ret["cpu_cores"] = getCpuCores();
    ret["cpu_mhz"] = double(getCpuMHz());
    getMemory(ret);
    return ret;
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
    catch(...)
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
    catch(...)
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
    catch(...)
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
    catch(...)
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
    catch(...)
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
    catch(...)
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

#ifdef __cplusplus
}
#endif