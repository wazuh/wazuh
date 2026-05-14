/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * May 16, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "utilsWrapperMac.hpp"
#include "cmdHelper.h"

std::string UtilsWrapperMac::exec(const std::string& cmd, const size_t bufferSize)
{
    return Utils::exec(cmd, bufferSize);
}
