/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"

static std::string getSerialNumber()
{
    const auto rawData{Utils::exec("system_profiler SPHardwareDataType | grep Serial")}
    return Utils::trim(rawData.substr(rawData.find(":")), " \t\r\n");
}

nlohmann::json SysInfo::hardware()
{
    nlohmann::json ret;
    ret["board_serial"] = getSerialNumber();
    return ret;
}