/* Copyright (C) 2015-2021, Wazuh Inc.
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
#include "external/audit-userspace/auparse/auparse.h"

#define WHODATA_PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)

#define AUDIT_HEALTHCHECK_KEY "wazuh_hc"
#define AUDIT_KEY "wazuh_fim"

typedef struct {
    char *path;
    int pending_removal;
} whodata_directory_t;

typedef enum _whodata_mode_s { READING_MODE = 0, HEALTHCHECK_MODE } whodata_mode_t;

typedef struct _audit_data_s {
    int socket;
    audit_mode mode;
    whodata_mode_t wmode;
    auparse_state_t *parser;
} audit_data_t;

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

void healthcheck_callback(auparse_state_t *state, auparse_cb_event_t cb_event_type, void *);

/**
 * @brief Read an audit event from socket
 *
 * @param [out] audit_sock The audit socket to read the events from
 * @param [in] reading_mode READING_MODE or HEALTHCHECK_MODE
 */
void audit_read_events(audit_data_t *audit_data);

/**
 * @brief Generate the audit event that the healthcheck thread should read
 *
 * @param audit_socket The audit socket to read the events from
 * @return 0 on success, -1 on error
 */
int audit_health_check(audit_data_t *audit_data);

void whodata_callback(auparse_state_t *state, auparse_cb_event_t cb_event_type, void *_unused);

extern pthread_mutex_t audit_mutex;
extern volatile int audit_thread_active;
extern volatile int hc_thread_active;
extern unsigned int count_reload_retries;
extern volatile int audit_health_check_creation;
#endif // SYSCHECK_AUDIT_H
