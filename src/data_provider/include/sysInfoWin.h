/*
 * Wazuh SysInfoWin
 * Copyright (C) 2024, Wazuh Inc.
 * November 8, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYS_INFO_WIN_H
#define _SYS_INFO_WIN_H

/* Hotfixes APIs */
#include <wbemidl.h>
#include <wbemcli.h>
#include <comdef.h>
#include <codecvt>
#include "wuapi.h"



// Define GUID manually for CLSID_UpdateSearcher
DEFINE_GUID(CLSID_UpdateSearcher, 0x5A2A5E6E, 0xD633, 0x4C3A, 0x8A, 0x7E, 0x69, 0x4D, 0xBF, 0x9E, 0xCE, 0xD4);

// Queries Windows Management Instrumentation (WMI) to retrieve installed hotfixes
//  and stores them in the provided set.
void QueryWMIHotFixes(std::set<std::string>& hotfixSet);

// Queries Windows Update Agent (WUA) for installed update history,
// extracts hotfixes, and adds them to the provided set.
void QueryWUHotFixes(std::set<std::string>& hotfixSet);

#endif //_SYS_INFO_WIN_H
