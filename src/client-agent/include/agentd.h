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

/* Parse read config into JSON format */
cJSON *getClientConfig(void);
cJSON *getAgentInternalOptions(void);
#ifndef WIN32
cJSON *getAntiTamperingConfig(void);
#endif

/* Agentd init function */
void AgentdStart(int uid, int gid, const char *user, const char *group) __attribute__((noreturn));

/* Event Forwarder */
void *EventForward(void);

/* Read the keys, arm the startup gate and report the agent start */
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
void startup_gate_check_manager_config_hash(const char *manager_sha256);

// Read current startup gate state.
void startup_gate_get_status(bool *ready, char *reason, size_t reason_size);

// Query startup gate state.
bool startup_gate_is_ready(void);

size_t agcom_dispatch(char * command, char ** output);
size_t agcom_getconfig(const char * section, char ** output);
size_t agcom_getallconfig(char ** output);
size_t agcom_getallstats(char ** output);

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
extern char agent_cluster_node[256];
extern char agent_agent_groups[OS_SIZE_65536];

static const char AG_IN_UNMERGE[] = "wazuh: Could not unmerge shared file.";

#endif /* AGENTD_H */
