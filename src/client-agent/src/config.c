/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_xml.h"
#include "os_regex.h"
#include "os_net.h"
#include "agentd.h"
#include "module_limits.h"

/* Global variables */
int run_foreground;
keystore keys;
agent *agt;
#ifndef WIN32
anti_tampering *atc;
#endif
int remote_conf;
int rotate_log;
int agent_debug_level;

/* Agent's handshake globals */
module_limits_t agent_module_limits;
char agent_cluster_name[256] = {0};
char agent_agent_groups[OS_SIZE_65536] = {0};

/* Guards agent_cluster_name/agent_agent_groups: written by the
 * connection thread on every (re)connect handshake, read by the agcom "gethandshake"
 * responder, which agent-info now polls periodically instead of only once at startup. */
pthread_mutex_t agent_handshake_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Read the config file (for the remote client) */
int ClientConf(const char *cfgfile)
{
    int modules = 0;

    agt->server = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;
    agt->flags.auto_restart = 1;
    agt->notify_time = 0;
    agt->max_time_reconnect_try = 0;
    agt->main_ip_update_interval = 0;
    agt->server_count = 0;

    /* The shipped configuration carries no <ssl> block, so this is the posture most
     * agents actually run with -- as is any config written before the HTTPS transport
     * existed. It is not the enum's zero value (FULL), which would make every one of
     * those agents refuse to start on a missing CA, so it has to be set by hand. */
    agt->ssl.verification_mode = AGENT_VERIFY_NONE;

    /* <config_report> ships enabled: the manager needs the periodic /config snapshot
     * even on a config nobody touched. It is not the struct's zero value, so it has
     * to be set by hand -- an explicit <enabled>no</enabled> still overrides this,
     * since Read_Agent_Report() only writes the field when the tag is present. */
    agt->config_report.enabled = 1;

    /* <stats_report>/<config_report><interval>: the effective default, set here
     * instead of left at zero, so anything reading agt directly (e.g. the /config
     * JSON dump) shows the real value instead of "0" -- Read_Agent_Report() rejects
     * an explicit <interval>0</interval> outright, so zero can never be a legitimate
     * value it wrote, and the transport module's own zero-means-unset fallback
     * (moduleConfig.cpp) never actually sees a zero from here as a result. */
    agt->stats_report.interval = 60;
    agt->config_report.interval = 3600;

    agt->batch.interval = 10;

#ifndef WIN32
    atc->package_uninstallation = false;
#endif

    modules |= CCLIENT;

    /* <agent><enrollment> defaults (#38465): a by-value struct now, like
     * <ssl>/<batch> above -- set by hand before parsing, the same convention
     * this function already uses for those. */
    agt->enrollment.enabled = true;
    agt->enrollment.agent_name = NULL;
    agt->enrollment.groups = NULL;
    agt->enrollment.agent_address = NULL;
    agt->enrollment.use_source_ip = false;
    os_strdup(AUTHD_PASS, agt->enrollment.authorization_pass_path);
    agt->enrollment.delay_after_enrollment = 20;

    if (ReadConfig(modules, cfgfile, agt, NULL) < 0) {
        return (OS_INVALID);
    }

    if(agt->flags.remote_conf = getDefine_Int("agent", "remote_conf", 0, 1), agt->flags.remote_conf) {
        remote_conf = agt->flags.remote_conf;
        ReadConfig(CCLIENT | CAGENT_CONFIG, AGENTCONFIG, agt, NULL);
    } else {
        remote_conf = 0;
    }
#ifndef WIN32
    if (ReadConfig(ATAMPERING, cfgfile, atc, NULL) < 0) {
        return OS_INVALID;
    }
#endif

    return (1);
}

/* Both agentd and the Windows agent gate startup on this, at the point where each can
 * still fail cleanly: before daemonizing on POSIX, before the first module thread on
 * Windows. Shared so the two can never drift apart on what counts as a usable CA. */
bool w_agent_validate_ssl_ca(const agent *cfg)
{
    const char *ca = cfg->ssl.certificate_authorities;

    /* Under 'none' the CA is never read, so a wrong path stays invisible until someone
     * enables verification -- and then the agent refuses to start. Warn while it is
     * still harmless rather than accepting it in silence. */
    if (cfg->ssl.verification_mode == AGENT_VERIFY_NONE) {
        if (ca && !w_is_file(ca)) {
            mwarn(AG_UNUSED_SSL_CA, ca);
        }

        return true;
    }

    /* 'system' trusts the OS store instead of an operator-supplied file: a configured CA
     * would be silently unused, which is worth failing closed on rather than guessing which
     * one the operator actually meant. On Windows/macOS the OS store is asked for natively
     * (no file to probe for); on Linux the https_client module itself fails closed if no
     * known OS bundle is found (moduleConfig.cpp's validateTls), mirroring this same check
     * one layer up so a bad config is caught before the module ever spins up threads. */
    if (cfg->ssl.verification_mode == AGENT_VERIFY_SYSTEM) {
        if (ca) {
            merror(AG_SSL_CA_FORBIDDEN_SYSTEM, ca);
            return false;
        }

#if !defined(WIN32) && !defined(__APPLE__)
        if (os_find_ca_bundle(NULL) == NULL) {
            merror(AG_SSL_SYSTEM_NO_BUNDLE);
            return false;
        }
#endif

        return true;
    }

    /* A verifying mode without a readable CA can never connect: the https_client module
     * fails closed on this, per its own validation. */
    if (!ca || !w_is_file(ca)) {
        merror(AG_INV_SSL_CA, ca ? ca : "");
        return false;
    }

    return true;
}

// Helper for translating the verification_mode enum to a string for JSON output.
static const char *w_agent_verify_mode_str(int verification_mode)
{
    switch (verification_mode) {
    case AGENT_VERIFY_FULL:
        return "full";
    case AGENT_VERIFY_CERT:
        return "certificate";
    case AGENT_VERIFY_NONE:
        return "none";
    case AGENT_VERIFY_SYSTEM:
        return "system";
    default:
        return "unknown";
    }
}

cJSON *getAgentConfig(void) {

    if (!agt) {
        return NULL;
    }

    unsigned int i;
    cJSON *root = cJSON_CreateObject();
    cJSON *agent_config = cJSON_CreateObject();

    if (agt->profile) cJSON_AddStringToObject(agent_config,"config-profile",agt->profile);
    cJSON_AddNumberToObject(agent_config,"notify_time",agt->notify_time);
    cJSON_AddNumberToObject(agent_config,"time-reconnect",agt->max_time_reconnect_try);
    cJSON_AddNumberToObject(agent_config,"ip_update_interval",agt->main_ip_update_interval);
    if (agt->flags.auto_restart) cJSON_AddStringToObject(agent_config,"auto_restart","yes"); else cJSON_AddStringToObject(agent_config,"auto_restart","no");
    if (agt->flags.remote_conf) cJSON_AddStringToObject(agent_config,"remote_conf","yes"); else cJSON_AddStringToObject(agent_config,"remote_conf","no");
    if (agt->server) {
        cJSON *servers = cJSON_CreateArray();
        for (i=0;agt->server[i].rip;i++) {
            cJSON *server = cJSON_CreateObject();
            cJSON_AddStringToObject(server, "address", agt->server[i].rip);
            cJSON_AddNumberToObject(server, "port", agt->server[i].port);

            if (agt->server[i].endpoint)
                cJSON_AddStringToObject(server, "endpoint", agt->server[i].endpoint);

            if (agt->server[i].scope_id)
                cJSON_AddNumberToObject(server, "scope_id", agt->server[i].scope_id);

            cJSON_AddNumberToObject(server, "max_retries", agt->server[i].max_retries);
            cJSON_AddNumberToObject(server, "retry_interval", agt->server[i].retry_interval);

            cJSON_AddItemToArray(servers,server);
        }
        cJSON_AddItemToObject(agent_config,"manager",servers);
    }

    {
        cJSON *enrollment_cfg = cJSON_CreateObject();
        cJSON_AddStringToObject(enrollment_cfg, "enabled", agt->enrollment.enabled ? "yes" : "no");
        cJSON_AddNumberToObject(enrollment_cfg, "delay_after_enrollment", agt->enrollment.delay_after_enrollment);

        if (agt->enrollment.agent_name)
            cJSON_AddStringToObject(enrollment_cfg, "agent_name", agt->enrollment.agent_name);
        if (agt->enrollment.groups)
            cJSON_AddStringToObject(enrollment_cfg, "group", agt->enrollment.groups);
        if (agt->enrollment.agent_address)
            cJSON_AddStringToObject(enrollment_cfg, "agent_address", agt->enrollment.agent_address);
        cJSON_AddStringToObject(enrollment_cfg, "use_source_ip", agt->enrollment.use_source_ip ? "yes" : "no");
        if (agt->enrollment.authorization_pass_path)
            cJSON_AddStringToObject(enrollment_cfg, "authorization_pass_path", agt->enrollment.authorization_pass_path);

        cJSON_AddItemToObject(agent_config,"enrollment",enrollment_cfg);
    }
    // <ssl>
    cJSON *ssl = cJSON_CreateObject();
    cJSON_AddStringToObject(ssl, "verification_mode", w_agent_verify_mode_str(agt->ssl.verification_mode));
    if (agt->ssl.certificate) cJSON_AddStringToObject(ssl, "certificate", agt->ssl.certificate);
    if (agt->ssl.key) cJSON_AddStringToObject(ssl, "key", agt->ssl.key);
    if (agt->ssl.certificate_authorities) cJSON_AddStringToObject(ssl, "certificate_authorities", agt->ssl.certificate_authorities);
    if (agt->ssl.ciphers) cJSON_AddStringToObject(ssl, "ciphers", agt->ssl.ciphers);
    cJSON_AddItemToObject(agent_config, "ssl", ssl);

    // <batch>
    cJSON *batch = cJSON_CreateObject();
    /* Zero means <size> was never configured, and every reader of that zero applies
     * DEFAULT_BATCH_SIZE_BYTES, so the report states the cap actually in force rather
     * than the sentinel. Not seeded into agt: that value is passed on to
     * asp_set_session_max_bytes(), where a seed would read as an explicit setting. */
    cJSON_AddNumberToObject(batch, "size",
                            agt->batch.size > 0 ? agt->batch.size : DEFAULT_BATCH_SIZE_BYTES);
    cJSON_AddNumberToObject(batch, "interval", agt->batch.interval);
    cJSON_AddItemToObject(agent_config, "batch", batch);

    /* The two periodic report pushes (#37843). Reported so the /config document
     * says whether the agent is reporting, and on what cadence. */
    cJSON *stats_report = cJSON_CreateObject();
    cJSON_AddStringToObject(stats_report, "enabled", agt->stats_report.enabled ? "yes" : "no");
    cJSON_AddNumberToObject(stats_report, "interval", agt->stats_report.interval);
    cJSON_AddItemToObject(agent_config, "stats_report", stats_report);

    cJSON *config_report = cJSON_CreateObject();
    cJSON_AddStringToObject(config_report, "enabled", agt->config_report.enabled ? "yes" : "no");
    cJSON_AddNumberToObject(config_report, "interval", agt->config_report.interval);
    cJSON_AddItemToObject(agent_config, "config_report", config_report);

    cJSON_AddItemToObject(root, "agent", agent_config);

    return root;
}

#ifndef WIN32
cJSON *getAntiTamperingConfig(void) {

    if (!atc) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *package_uninstallation = cJSON_CreateObject();

    if (atc->package_uninstallation) cJSON_AddStringToObject(package_uninstallation,"package_uninstallation","yes"); else cJSON_AddStringToObject(package_uninstallation,"package_uninstallation","no");

    cJSON_AddItemToObject(root, "package_uninstallation", package_uninstallation);

    return root;
}
#endif

cJSON *getAgentInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON *agent = cJSON_CreateObject();

#ifdef WIN32
    cJSON_AddNumberToObject(agent,"debug",win_debug_level);
#else
    cJSON_AddNumberToObject(agent,"debug",agent_debug_level);
#endif
    /* Read from the internal options: the globals that held these lived in the
     * retired buffer.c/request.c. */
    const int warn_level = getDefine_Int("agent", "warn_level", 1, 100);
    cJSON_AddNumberToObject(agent,"warn_level",warn_level);
    cJSON_AddNumberToObject(agent,"normal_level",getDefine_Int("agent", "normal_level", 0, warn_level - 1));
    cJSON_AddNumberToObject(agent,"tolerance",getDefine_Int("agent", "tolerance", 0, 600));
    cJSON_AddNumberToObject(agent,"state_interval",interval);
    cJSON_AddNumberToObject(agent,"remote_conf",remote_conf);

    cJSON_AddItemToObject(internals,"agent",agent);

    cJSON *monitord = cJSON_CreateObject();

    cJSON_AddNumberToObject(monitord,"rotate_log",rotate_log);
    cJSON_AddNumberToObject(monitord,"compress",log_compress);
    cJSON_AddNumberToObject(monitord,"keep_log_days",keep_log_days);
    cJSON_AddNumberToObject(monitord,"day_wait",day_wait);
    cJSON_AddNumberToObject(monitord,"size_rotate",size_rotate_read);
    cJSON_AddNumberToObject(monitord,"daily_rotations",daily_rotations);

    cJSON_AddItemToObject(internals,"monitord",monitord);

    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}
