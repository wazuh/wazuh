/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYSCHECK_AUDIT_H
#define SYSCHECK_AUDIT_H

#include "shared.h"
#include "../syscheck.h"
#include "audit_op.h"

#define WHODATA_PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)

#define AUDIT_HEALTHCHECK_KEY "wazuh_hc"
#define AUDIT_KEY "wazuh_fim"

// Public rule handlig functions
int audit_rules_init();

// Public parse parse functions
void clean_regex();

extern pthread_mutex_t audit_mutex;
extern volatile int audit_thread_active;
extern volatile int hc_thread_active;
extern int audit_rule_manipulation;
extern unsigned int count_reload_retries;
extern volatile int audit_health_check_creation;
#endif // SYSCHECK_AUDIT_H
