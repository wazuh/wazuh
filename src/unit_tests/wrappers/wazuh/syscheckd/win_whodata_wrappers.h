/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WIN_WHODATA_WRAPPERS_H
#define WIN_WHODATA_WRAPPERS_H

int __wrap_run_whodata_scan();

int __wrap_set_winsacl(const char *dir, int position);

int __wrap_whodata_audit_start();

#endif
