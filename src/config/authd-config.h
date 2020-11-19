/*
 * Authd settings manager
 * Copyright (C) 2015-2020, Wazuh Inc.
 * May 29, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#define AD_CONF_UNPARSED 3
#define AD_CONF_UNDEFINED 2

typedef struct authd_flags_t {
    unsigned short disabled:3;
    unsigned short use_source_ip:1;
    unsigned short force_insert:1;
    unsigned short clear_removed:1;
    unsigned short use_password:1;
    unsigned short verify_host:1;
    unsigned short auto_negotiate:1;
} authd_flags_t;

typedef struct authd_config_t {
    unsigned short port;
    authd_flags_t flags;
    int force_time;
    char *ciphers;
    char *agent_ca;
    char *manager_cert;
    char *manager_key;
    long timeout_sec;
    long timeout_usec;
    bool worker_node;
} authd_config_t;
