/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SYSCHECK_AUDIT_WRAPPERS
#define SYSCHECK_AUDIT_WRAPPERS

void __wrap_audit_read_events(int *audit_sock, int mode);

int __wrap_init_auditd_socket(void);
#endif // SYSCHECK_AUDIT_WRAPPERS
