/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WINNETWK_WRAPPERS_H
#define WINNETWK_WRAPPERS_H

#include <windef.h>
#include <winbase.h>

#undef WNetGetConnectionA
#define WNetGetConnectionA wrap_WNetGetConnectionA

DWORD wrap_WNetGetConnectionA(LPCSTR  lpLocalName,
                              LPSTR   lpRemoteName,
                              LPDWORD lpnLength);

#endif
