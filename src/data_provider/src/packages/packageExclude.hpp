/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_EXCLUDE_HPP
#define _PACKAGE_EXCLUDE_HPP

#include <unordered_set>

void getExcludePackages(std::unordered_set<std::string>& excludedPaths);

#endif // _PACKAGE_EXCLUDE_HPP
