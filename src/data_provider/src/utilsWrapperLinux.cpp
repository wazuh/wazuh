/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "utilsWrapperLinux.hpp"
#include "cmdHelper.h"
#include "filesystemHelper.h"

std::string UtilsWrapper::exec(const std::string& cmd, const size_t bufferSize)
{
    return Utils::exec(cmd, bufferSize);
}

bool UtilsWrapper::existsRegular(const std::string& path)
{
    return Utils::existsRegular(path);
}
