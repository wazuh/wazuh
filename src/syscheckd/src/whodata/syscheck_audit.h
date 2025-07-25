/* Copyright (C) 2015, Wazuh Inc.
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
#include "syscheck.h"
#include "../file/file.h"
#include "audit_op.h"

#define WHODATA_PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)

#define AUDIT_HEALTHCHECK_KEY "wazuh_hc"
#define AUDIT_KEY "wazuh_fim"

typedef struct {
    char *path;
    int pending_removal;
} whodata_directory_t;

typedef enum audit_key_type {
    FIM_AUDIT_UNKNOWN_KEY = 0,
    FIM_AUDIT_KEY,
    FIM_AUDIT_HC_KEY,
    FIM_AUDIT_CUSTOM_KEY
} audit_key_type;

/**
 * @brief Checks if the manipulation of the audit rule was done by FIM or by an user

 * @return The remaining audit events:
 * @retval 0: The modification wasn't done by FIM.
 * @retval Positive integer: Number of remaining CONFIG_CHANGE events done by FIM.
 */
int fim_manipulated_audit_rules();

/**
 * @brief Initialize the list responsible for holding the configured audit rules.
 *
 * @return 0 if all goes well, -1 in case of an error.
 */
int fim_audit_rules_init();

/**
 * @brief Sweeps the configured directories and loads the required rules into audit.
 *
 * @return The amount of rules loaded.
 */
int fim_rules_initial_load();

// Public parse functions
void clean_regex();

extern pthread_mutex_t audit_mutex;
extern atomic_int_t audit_thread_active;
extern atomic_int_t hc_thread_active;
extern atomic_int_t audit_health_check_creation;
extern unsigned int count_reload_retries;
#endif // SYSCHECK_AUDIT_H
