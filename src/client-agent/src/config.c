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

/* Enrollment retry ramp, shared by the initial-enrollment loop (start_agent.c) and the
 * re-enrollment one (https_client_bridge.c). */
#define ENROLLMENT_RETRY_MAX_S_DEFAULT   60
#define ENROLLMENT_RETRY_DELTA_S_DEFAULT 5

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

    /* Left UNSET so w_agent_resolve_ssl_posture() can tell "the operator said nothing" from
     * "the operator said none", which decide different things. Never left UNSET past this
     * function returning -- see the call at the end. */
    agt->ssl.verification_mode = AGENT_VERIFY_UNSET;

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

    /* Before both enrollment loops (main.c and win_utils.c call this ahead of AgentdStart()), so an
     * out-of-range value refuses the start instead of killing the agent at its first failed
     * re-enrollment. */
    agt->enrollment.retry_max =
        getDefine_Int_default("agent", "enrollment_retry_max", 1, 86400, ENROLLMENT_RETRY_MAX_S_DEFAULT);
    agt->enrollment.retry_delta =
        getDefine_Int_default("agent", "enrollment_retry_delta", 1, 3600, ENROLLMENT_RETRY_DELTA_S_DEFAULT);

#ifndef WIN32
    if (ReadConfig(ATAMPERING, cfgfile, atc, NULL) < 0) {
        return OS_INVALID;
    }
#endif

    /* Last, so it sees everything ossec.conf had to say about <ssl>. Deliberately below the
     * ATAMPERING read above rather than beside the CCLIENT one: a resolver that ran before a
     * path which can still return OS_INVALID would leave "resolved" and "ClientConf
     * succeeded" as separate facts, and the only net under that mistake is
     * bridge_map_verify_mode()'s UNSET guard. */
    w_agent_resolve_ssl_posture(agt);

    return (1);
}

/* Settles what the agent will actually do about TLS, from two inputs: what <ssl> said, and
 * whether a usable trust anchor is on disk (#38940 requirements 4 and 13). There is no
 * single default any more -- it is a ladder, and 'none' is only its last rung:
 *
 *     explicit <verification_mode>                 -> honoured
 *     explicit <certificate_authorities>, no mode  -> certificate (mirrors remote-config.c)
 *     anchor file present, no mode                 -> full, the anchor is the CA
 *     nothing at all                               -> none, nothing to verify against
 *
 * That last rung is 'none' rather than 'system' because on a stock install there is nothing
 * for the OS trust store to succeed against: the manager's certificate is signed by its own
 * root-ca.pem, which is in no OS store, so 'system' could only ever refuse to connect -- and
 * on a Linux host with no OS bundle at all it refuses to even start, (4121). An install that
 * has been given no trust material verifies nothing and says so, per #38940 requirement 5
 * and section 3.1 of the solution document; an install that has been given the anchor takes
 * the rung above and verifies. 'system' stays available, as an explicit choice for a fleet
 * whose manager is fronted by a publicly trusted certificate.
 *
 * The anchor also overrides an explicit 'none': a configuration-management template that
 * writes none -- which is what every current Ansible and Puppet role does -- must not be
 * able to turn verification off on a host that holds an anchor and can therefore verify.
 * That override logs at error level and never refuses to start: taking a host off the air
 * is the wrong answer to a careless template, and the security property is the same either
 * way. An explicit 'certificate' or 'system' still wins, so a corporate-PKI fleet is not
 * forced onto the anchor.
 *
 * Shared configuration cannot reach any of this: Read_Agent_Shared() recognizes only
 * <batch>/force_reconnect_interval under <agent> and rejects <ssl> outright, so the manager
 * cannot push a verification posture. That restriction is intentional and is preserved.
 *
 * Runs once, here. An anchor written afterwards -- by a bootstrap that fetched it from the
 * manager, say -- is invisible until reloadAgent() re-runs ClientConf() from scratch, so a
 * future caller must either sequence its write before this point or call this again
 * (#39026, #39027). Idempotent, so calling it twice is safe. */
void w_agent_resolve_ssl_posture(agent *cfg)
{
    /* Probed once, up front, and reused: every branch below needs the same answer, and one
     * discarded open on the 'system' path is cheaper than reasoning about how many times
     * this ran. w_is_file() is an openability check -- the same probe
     * w_agent_validate_ssl_ca() already applies to a configured CA -- so "usable" here means
     * no more than "present and readable by whoever is running". A malformed, truncated or
     * expired anchor still counts as present and is caught later, by the transport module's
     * own validation and then by the handshake; detecting it here is #38949 question 10.
     * Note the euid difference that comes with that: this runs as root, before the privilege
     * drop, while the module opens the same file as the wazuh user on every request, so an
     * anchor readable here is not necessarily readable there (#38949 questions 4 and 8). */
    const bool anchor = w_is_file(AGENT_ANCHOR_CA) != 0;

    /* A present-but-empty <certificate_authorities/> (or <certificate_authorities>
     * </certificate_authorities>) is not a real CA -- w_agent_validate_ssl_ca() will still
     * fail closed on it either way, but treating it as configured here would warn that a CA
     * is set when none actually was, and would block the anchor from filling the gap. */
    bool ca_set = cfg->ssl.certificate_authorities != NULL && *cfg->ssl.certificate_authorities != '\0';

    if (cfg->ssl.verification_mode == AGENT_VERIFY_UNSET) {
        if (ca_set) {
            mwarn("The '<ssl><certificate_authorities>' option is configured but "
                  "'<verification_mode>' is not; defaulting '<verification_mode>' to 'certificate'.");
            cfg->ssl.verification_mode = AGENT_VERIFY_CERT;
        } else if (anchor) {
            cfg->ssl.verification_mode = AGENT_VERIFY_FULL;
        } else {
            cfg->ssl.verification_mode = AGENT_VERIFY_NONE;
        }
    } else if (cfg->ssl.verification_mode == AGENT_VERIFY_NONE && anchor) {
        merror(AG_SSL_ANCHOR_OVERRIDES_NONE, AGENT_ANCHOR_CA);
        cfg->ssl.verification_mode = AGENT_VERIFY_FULL;

        /* Whatever path 'none' was carrying is dropped in favour of the anchor, readable or
         * not. Under 'none' it was never going to be read, so nothing has ever proved it
         * usable -- and keeping it would turn this override into a (4118) refusal to start,
         * which is precisely the outcome requirement 13 rules out. That is also why this row
         * and its verifying-mode counterpart end differently: an unreadable CA under 'full'
         * still refuses, because there requirement 13 does not apply and a named (4118) beats
         * silently verifying against a CA the operator never asked for.
         *
         * Say so when a path is actually being discarded: otherwise the agent reports 'full'
         * plus a CA nobody configured, and the operator's own path leaves no trace. */
        if (ca_set) {
            mwarn(AG_SSL_ANCHOR_IGNORES_CA, cfg->ssl.certificate_authorities, AGENT_ANCHOR_CA);
        }

        ca_set = false;
    }

    /* The anchor is the default <certificate_authorities>: one rule, rather than a special
     * case per mode. An explicit path wins in every verifying mode -- but not under 'none',
     * which dropped its own path above rather than refuse to start. 'system' is excluded on
     * purpose -- it
     * trusts the OS store instead of a file, and a CA set alongside it is a hard (4120)
     * refusal, so injecting here would refuse to start every agent that holds an anchor.
     * 'none' cannot reach this either: with an anchor it became 'full' above, and without
     * one there is nothing to inject. */
    if ((cfg->ssl.verification_mode == AGENT_VERIFY_FULL || cfg->ssl.verification_mode == AGENT_VERIFY_CERT)
            && !ca_set && anchor) {
        /* os_free() first: os_strdup() overwrites the pointer without releasing it, and an
         * empty <certificate_authorities/> left a real allocation behind. Heap, never the
         * constant itself -- Free_Agent() frees this field. */
        os_free(cfg->ssl.certificate_authorities);
        os_strdup(AGENT_ANCHOR_CA, cfg->ssl.certificate_authorities);
    }
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
        /* A present-but-empty <certificate_authorities/> is not a real CA --
         * w_agent_resolve_ssl_posture() already treats it that way (it does not infer
         * 'certificate' from it), so this check has to agree, or an operator who reaches
         * 'system' with that exact shape is refused a start over a CA that isn't really
         * set. */
        if (ca && *ca != '\0') {
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
