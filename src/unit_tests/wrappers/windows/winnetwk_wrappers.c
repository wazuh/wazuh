/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "winnetwk_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

DWORD wrap_WNetGetConnectionA(LPCSTR  lpLocalName,
                              __UNUSED_PARAM(LPSTR   lpRemoteName),
                              __UNUSED_PARAM(LPDWORD lpnLength)) {
    return (lpLocalName && lpLocalName[0] == 'Z' && lpLocalName[1] == ':') ? NO_ERROR : ERROR_NOT_CONNECTED;
}
