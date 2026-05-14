/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SDDL_WRAPPERS_H
#define SDDL_WRAPPERS_H

#include <windows.h>

#undef  ConvertSidToStringSid
#define ConvertSidToStringSid wrap_ConvertSidToStringSid

WINBOOL wrap_ConvertSidToStringSid(PSID Sid, LPSTR *StringSid);

void expect_ConvertSidToStringSid_call(LPSTR StringSid, int ret_value);

#endif
