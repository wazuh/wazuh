/*
 * Authd settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 29, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AUTH_CONFIG_H
#define AUTH_CONFIG_H

#define AD_CONF_UNPARSED 3
#define AD_CONF_UNDEFINED 2

#define AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT false    ///< Default allow_higher_versions value (false)

#include <time.h>

/**
 * @brief Structure that defines the force options for agent replacement.
 **/
typedef struct authd_force_options_t {
    bool enabled;                    ///< Sets to enabled or disabled the force options for agent replacement
    bool key_mismatch;               ///< Sets to enabled or disabled the key_mismatch auth setting
    bool disconnected_time_enabled;  ///< Sets to enabled or disabled the disconnected_time auth setting
    time_t disconnected_time;        ///< Sets the time to be used by the disconnected_time auth setting if enabled
    time_t after_registration_time;  ///< Sets the time to be used by the after_registration_time auth setting
} authd_force_options_t;

typedef struct authd_flags_t {
    unsigned short disabled:3;
    unsigned short use_source_ip:1;
    unsigned short clear_removed:1;
    unsigned short use_password:1;
    unsigned short verify_host:1;
    unsigned short auto_negotiate:1;
    unsigned short remote_enrollment:1;
} authd_flags_t;

typedef struct authd_key_request_t {
    int             enabled;
    char            *exec_path;
    char            *socket;
    unsigned int    timeout;
    unsigned int    threads;
    unsigned int    queue_size;
    unsigned short  compatibility_flag; // Flag to avoid overwriting configuration settings
} authd_key_request_t;

typedef struct authd_config_t {
    unsigned short port;
    authd_flags_t flags;
    authd_force_options_t force_options;
    authd_key_request_t key_request;
    char *ciphers;
    char *agent_ca;
    char *manager_cert;
    char *manager_key;
    long timeout_sec;
    long timeout_usec;
    bool worker_node;
    bool ipv6;
    bool allow_higher_versions;
} authd_config_t;

/**
 * @brief It converts a time string with the format <time><unit>, where the unit could be
 *        d (days), h (hours), m (minutes), or s (seconds), to a representation in seconds saved
 *        in a `time_t` variable.
 *        The time unit is optional. If not provided, it is assumed as seconds.
 *
 * @param syscheck String with the format <time><unit>.
 * @param interval The variable to save the time conversion.
 * @retval OS_INVALID in case of error. OS_SUCCES otherways.
 */
int get_time_interval(char *source, time_t *interval);

#endif
