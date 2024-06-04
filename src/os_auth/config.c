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

#include "shared.h"
#include "auth.h"
#include "config/config.h"

// Read configuration
int authd_read_config(const char *path) {
    config.port = DEFAULT_PORT;
    config.key_request.compatibility_flag = 0;
    config.key_request.exec_path = NULL;
    config.key_request.socket = NULL;
    config.allow_higher_versions = AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;

    mdebug2("Reading configuration '%s'", path);

    if (ReadConfig(CAUTHD, path, &config, NULL) < 0) {
        return OS_INVALID;
    }

    if (!config.ciphers) {
        config.ciphers = strdup(DEFAULT_CIPHERS);
    }

    switch (config.flags.disabled) {
    case AD_CONF_UNPARSED:
        config.flags.disabled = 1;
        break;
    case AD_CONF_UNDEFINED:
        config.flags.disabled = 0;
    }

    config.timeout_sec = getDefine_Int("auth", "timeout_seconds", 0, INT_MAX);
    config.timeout_usec = getDefine_Int("auth", "timeout_microseconds", 0, 999999);

    return 0;
}

#ifndef CLIENT

cJSON *getAuthdConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *auth = cJSON_CreateObject();
    cJSON *key_request = cJSON_CreateObject();
    cJSON *force = cJSON_CreateObject();
    cJSON *disconnected_time = cJSON_CreateObject();

    cJSON_AddNumberToObject(auth,"port",config.port);
    if (config.flags.disabled) cJSON_AddStringToObject(auth,"disabled","yes"); else cJSON_AddStringToObject(auth,"disabled","no");
    if (config.flags.remote_enrollment) cJSON_AddStringToObject(auth,"remote_enrollment","yes"); else cJSON_AddStringToObject(auth,"remote_enrollment","no");
    if (config.ipv6) cJSON_AddStringToObject(auth,"ipv6","yes"); else cJSON_AddStringToObject(auth,"ipv6","no");
    if (config.flags.use_source_ip) cJSON_AddStringToObject(auth,"use_source_ip","yes"); else cJSON_AddStringToObject(auth,"use_source_ip","no");
    if (config.flags.clear_removed) cJSON_AddStringToObject(auth,"purge","yes"); else cJSON_AddStringToObject(auth,"purge","no");
    if (config.flags.use_password) cJSON_AddStringToObject(auth,"use_password","yes"); else cJSON_AddStringToObject(auth,"use_password","no");
    if (config.flags.verify_host) cJSON_AddStringToObject(auth,"ssl_verify_host","yes"); else cJSON_AddStringToObject(auth,"ssl_verify_host","no");
    if (config.flags.auto_negotiate) cJSON_AddStringToObject(auth,"ssl_auto_negotiate","yes"); else cJSON_AddStringToObject(auth,"ssl_auto_negotiate","no");
    if (config.ciphers) cJSON_AddStringToObject(auth,"ciphers",config.ciphers);
    if (config.agent_ca) cJSON_AddStringToObject(auth,"ssl_agent_ca",config.agent_ca);
    if (config.manager_cert) cJSON_AddStringToObject(auth,"ssl_manager_cert",config.manager_cert);
    if (config.manager_key) cJSON_AddStringToObject(auth,"ssl_manager_key",config.manager_key);
    if (config.key_request.enabled) cJSON_AddStringToObject(key_request, "enabled", "yes"); else cJSON_AddStringToObject(key_request, "enabled", "no");
    if (config.key_request.exec_path) cJSON_AddStringToObject(key_request, "exec_path", config.key_request.exec_path);
    if (config.key_request.socket) cJSON_AddStringToObject(key_request, "socket", config.key_request.socket);
    if (config.key_request.timeout) cJSON_AddNumberToObject(key_request, "timeout", config.key_request.timeout);
    if (config.key_request.threads) cJSON_AddNumberToObject(key_request, "threads", config.key_request.threads);
    if (config.key_request.queue_size) cJSON_AddNumberToObject(key_request, "queue_size", config.key_request.queue_size);
    cJSON_AddItemToObject(auth, "key_request", key_request);

    if (config.force_options.enabled) cJSON_AddStringToObject(force, "enabled", "yes"); else cJSON_AddStringToObject(force, "enabled", "no");
    if (config.force_options.key_mismatch) cJSON_AddStringToObject(force, "key_mismatch", "yes"); else cJSON_AddStringToObject(force, "key_mismatch", "no");
    if (config.force_options.disconnected_time_enabled) cJSON_AddStringToObject(disconnected_time, "enabled", "yes"); else cJSON_AddStringToObject(disconnected_time, "enabled", "no");
    if (config.force_options.disconnected_time) cJSON_AddNumberToObject(disconnected_time, "value", config.force_options.disconnected_time);
    cJSON_AddItemToObject(force, "disconnected_time", disconnected_time);
    if (config.force_options.after_registration_time) cJSON_AddNumberToObject(force, "after_registration_time", config.force_options.after_registration_time);
    cJSON_AddItemToObject(auth, "force", force);

    cJSON * agents = cJSON_CreateObject();
    cJSON_AddStringToObject(agents, "allow_higher_versions", config.allow_higher_versions ? "yes" : "no");
    cJSON_AddItemToObject(auth, "agents", agents);

    cJSON_AddItemToObject(root,"auth",auth);

    return root;
}

#endif
