/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENTD_H
#define AGENTD_H

#include "shared.h"
#include "sec.h"
#include "config.h"
#include "client-config.h"
#include "state.h"
#include "module_limits.h"

/* Client configuration */
int ClientConf(const char *cfgfile);

/* Check <ssl><certificate_authorities> against the configured verification mode.
 * Returns false when the agent must not start. */
bool w_agent_validate_ssl_ca(const agent *cfg);

/* Parse read config into JSON format */
cJSON *getAgentConfig(void);
cJSON *getAgentInternalOptions(void);
#ifndef WIN32
cJSON *getAntiTamperingConfig(void);
#endif

/* Agentd init function */
void AgentdStart(int uid, int gid, const char *user, const char *group) __attribute__((noreturn));

/* Event Forwarder */
void *EventForward(void);

/* Arm the startup gate and block until the agent has a valid key (enrolling
 * if needed). Must run before the HTTPS client is ever started: it validates
 * the key once, with no retry, so it must never see an empty keystore. */
void start_agent_prepare(void);

/* Publish the agent metadata and report the agent start. Must run after the
 * HTTPS client has started: it submits the start event through it. */
void start_agent(int is_startup);

/* Publish the agent metadata into shared memory */
void w_agentd_populate_metadata(void);

/**
 * Tries to enroll to a server indicated by server_rip
 * @return 0 on success -1 on error
 * @param server_rip the server ip where enrollment is attempted
 * @param network_interface network interface through which enrollment is attempted. (Required for IPv6 link-local addresses)
 * */
int try_enroll_to_server(const char *server_rip, uint32_t network_interface);

/**
 * Function that makes the request to the API for the request of uninstallation permissions.
 * @return true if validation is granted, false if denied
 * @param token API token used for the request
 * @param host host and port used for the request
 * @param ssl_verify Enable SSL verification
 * */
bool check_uninstall_permission(const char *token, const char *host, bool ssl_verify);

/**
 * Function to get the API token using a username and password
 * @return API token or NULL
 * @param userpass API user and password separated by colon
 * @param host host and port used for the request
 * @param ssl_verify Enable SSL verification
 * */
char* authenticate_and_get_token(const char *userpass, const char *host, bool ssl_verify);

/**
 * Function with all the necessary functionality to process the uninstallation validation of the Wazuh agent package.
 * @param uninstall_auth_token API token used for the request
 * @param uninstall_auth_login API user and password separated by colon
 * @param uninstall_auth_host host and port used for the request
 * @param ssl_verify Enable SSL verification
 * @return true if validation is granted, false if denied
 * */
bool package_uninstall_validation(const char *uninstall_auth_token, const char *uninstall_auth_login, const char *uninstall_auth_host, bool ssl_verify);

// Thread to rotate internal log
#ifdef WIN32
DWORD WINAPI w_rotate_log_thread(LPVOID arg);
#else
void * w_rotate_log_thread(void * arg);
#endif

// Reload agent
/* Trigger the reload chain via modulesd's control socket.
 * Returns true if the "reload" command was dispatched successfully
 * (Linux) or the detached restart process was spawned (Windows).
 * Returns false on Linux if the control socket could not be reached
 * after all retries — callers can use this as the signal to apply
 * a fallback (e.g. release the startup hash gate directly). */
bool reloadAgent(void);

// Restart agent (the https_client bridge's agent_restart task_type). Same mechanism and
// return-value contract as reloadAgent(), with wm_control dispatched
// "restart" instead of "reload" (systemctl/wazuh-control restart on
// Linux/macOS, a detached service restart on Windows).
bool restartAgent(void);

// Verify remote configuration. Return 0 on success or -1 on error.
int verifyRemoteConf();

// Initialize startup gate state for module workload blocking.
void startup_gate_initialize(void);

// Release the startup gate from the HTTPS /control apply chain
// (bridge_on_config_downloaded, once a downloaded config has been verified
// and applied).
void startup_gate_release_from_https_apply(void);

// Release the startup gate from the manager's per-Notify config_hash (SHA-256
// over merged.mg), independent of any download/reload having happened -- this
// is what covers an agent that boots already in sync with the manager.
// Suppressed while a download-driven apply is pending (see
// startup_gate_mark_download_pending()) so it cannot race ahead of that
// apply's own release.
void startup_gate_check_manager_config_hash(const char *manager_sha256);

// Mark that bridge_on_config_downloaded() is about to write a downloaded
// config to SHAREDCFG_FILE and (on success) drive a reload. Call before that
// write: from this point until startup_gate_release_from_https_apply() (or
// the next startup_gate_initialize()) runs, startup_gate_check_manager_config_hash()
// will not release the gate on its own, even though the just-written file's
// hash already matches the manager's -- that match is a side effect of this
// same download, not proof the reload it is driving has actually completed.
void startup_gate_mark_download_pending(void);

// Read current startup gate state.
void startup_gate_get_status(bool *ready, char *reason, size_t reason_size);

// Query startup gate state.
bool startup_gate_is_ready(void);

// Stricter than startup_gate_is_ready(): true only once margin_seconds have
// also elapsed since it opened. Used by report_query() (agent_report.c) so
// the /config and /stats collectors give the other daemons a grace period to
// finish opening their own command sockets after the gate releases them,
// instead of settling for whichever few happened to answer first.
bool startup_gate_is_settled(unsigned int margin_seconds);

// Grace period report_query() (agent_report.c) waits, on top of the startup
// gate itself, before trusting any component's answer. Declared here (rather
// than kept private to agent_report.c) so tests can compute a "definitely
// settled" timestamp without duplicating the number.
#define REPORT_STARTUP_SETTLE_SECONDS 5

size_t agcom_dispatch(char * command, char ** output);
size_t agcom_getconfig(const char * section, char ** output);
size_t agcom_getallconfig(char ** output);
size_t agcom_getallstats(char ** output);

/**
 * @brief Answer "getstate" with the agent state wrapped in the socket envelope.
 * @param output Pointer to store the allocated response string.
 * @return Length of the response string.
 */
size_t agcom_getstate(char ** output);

/**
 * @brief Collect every module's configuration into one /config document.
 *
 * Queries each agent daemon once and concatenates what they report.
 *
 * @return Allocated JSON document the caller frees, or NULL when no component
 *         answered and the cycle should be skipped.
 */
char *w_agent_collect_config(void);

/**
 * @brief Collect every module's statistics into one /stats document.
 *
 * @return Allocated JSON document the caller frees, or NULL when no component
 *         answered and the cycle should be skipped.
 */
char *w_agent_collect_stats(void);

#ifdef WIN32
size_t control_dispatch(char *command, char **output);
int os_start_service();
int os_stop_service();
#endif
size_t agcom_gethandshake(char ** output);
size_t agcom_getstartupgate(char **output);
cJSON *getDocumentLimits(const char *module);

#ifndef WIN32
void * agcom_main(void * arg);
#endif

/*** Global variables ***/
extern int agent_debug_level;
extern int win_debug_level;
extern int rotate_log;
extern int log_compress;
extern int keep_log_days;
extern int day_wait;
extern int daily_rotations;
extern int size_rotate_read;
extern int interval;
extern int remote_conf;


/* Global variables. Only modified during startup. */

extern int run_foreground;
extern keystore keys;
extern agent *agt;
extern anti_tampering *atc;

extern module_limits_t agent_module_limits;
extern char agent_cluster_name[256];
extern char agent_agent_groups[OS_SIZE_65536];
extern pthread_mutex_t agent_handshake_mutex;

static const char AG_IN_UNMERGE[] = "wazuh: Could not unmerge shared file.";

#endif /* AGENTD_H */
