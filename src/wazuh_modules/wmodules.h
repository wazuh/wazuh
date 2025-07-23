/*
 * Wazuh Module Manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 22, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef W_MODULES
#define W_MODULES

#include "shared.h"
#include <pthread.h>
#include "../config/config.h"
#include "wmodules_def.h"

#define WM_STATE_DIR    "var/wodles"               // Default directory for states.
#define WM_DIR_WIN      "wodles"                    // Default directory for states (Windows)
#define WM_STRING_MAX   67108864                    // Max. dynamic string size (64 MB).
#define WM_BUFFER_MAX   1024                        // Max. static buffer size.
#define WM_BUFFER_MIN   1024                        // Starting JSON buffer length.
#define WM_MAX_ATTEMPTS 3                           // Max. number of attempts.
#define WM_MAX_WAIT     500                           // Max. wait between attempts in milliseconds.
#define WM_IO_WRITE     0
#define WM_IO_READ      1
#define WM_ERROR_TIMEOUT 1                          // Error code for timeout.
#define WM_POOL_SIZE    8                           // Child process pool size.
#define WM_HEADER_SIZE  OS_SIZE_2048
#define VU_WM_NAME "vulnerability-detector"
#define AZ_WM_NAME "azure-logs"
#define KEY_WM_NAME "agent-key-polling"             // Deprecated key-polling module
#define SCA_WM_NAME "sca"
#define GCP_PUBSUB_WM_NAME "gcp-pubsub"
#define GCP_BUCKET_WM_NAME "gcp-bucket"
#define FLUENT_WM_NAME "fluent-forward"
#define AGENT_UPGRADE_WM_NAME "agent-upgrade"
#define TASK_MANAGER_WM_NAME "task-manager"
#define GITHUB_WM_NAME "github"
#define OFFICE365_WM_NAME "office365"
#define MS_GRAPH_WM_NAME "ms-graph"

#define WM_DEF_TIMEOUT      1800            // Default runtime limit (30 minutes)
#define WM_DEF_INTERVAL     86400           // Default cycle interval (1 day)
#define WM_MIN_UPDATE_INTERVAL 3600         // Minimum cycle update interval (1 hour)

#define DAY_SEC    86400
#define WEEK_SEC   604800

#define RANDOM_LENGTH  512
#define MAX_VALUE_NAME 16383

#define EXECVE_ERROR 0x7F

// Verification type
typedef enum crypto_type {
    MD5SUM,
    SHA1SUM,
    SHA256SUM
} crypto_type;

// Inclusion of modules

#include "wm_database.h"
#include "wm_syscollector.h"
#include "wm_command.h"
#include "wm_aws.h"
#include "wm_download.h"
#include "wm_azure.h"
#include "wm_docker.h"
#include "wm_sca.h"
#include "wm_fluent.h"
#include "wm_control.h"
#include "wm_gcp.h"
#include "wm_task_general.h"
#include "agent_upgrade/wm_agent_upgrade.h"
#include "task_manager/wm_task_manager.h"
#include "wm_github.h"
#include "wm_office365.h"
#include "wm_router.h"
#include "wm_content_manager.h"
#include "wm_vulnerability_scanner.h"
#include "wm_ms_graph.h"
#include "wm_harvester.h"

extern wmodule *wmodules;       // Loaded modules.
extern int wm_task_nice;        // Nice value for tasks.
extern int wm_max_eps;          // Maximum events per second sent by Wazuh Module
extern int wm_kill_timeout;     // Time for a process to quit before killing it
extern int wm_debug_level;

// Read XML configuration and internal options
int wm_config();
cJSON *getModulesConfig(void);
cJSON *getModulesInternalOptions(void);
int modulesSync(char* args);

// Add module to the global list
void wm_add(wmodule *module);

/*
 * @brief Get ID group of Wazuh user.
 *
 * @return ID group.
 */
gid_t wm_getGroupID(void);

/*
 * @brief Set ID group of wazuh modules
 *
 * @param[in] gid ID group.
 */
void wm_setGroupID(const gid_t gid);

// Check general configuration
int wm_check();

// Destroy configuration data
void wm_destroy();

// Destroy module
void wm_module_free(wmodule * config);

/* Execute command with timeout of secs. exitcode can be NULL.
 *
 * command is a mutable string.
 * output is a pointer to dynamic string. Caller is responsible for freeing it!
 * On success, return 0. On another error, returns -1.
 * If the called program timed-out, returns WM_ERROR_TIMEOUT and output may
 * contain data.
 * env_path is a pointer to an string to add to the PATH environment variable.
 */
int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);

#ifdef WIN32
// Add process to pool
void wm_append_handle(HANDLE hProcess);

// Remove process group from pool
void wm_remove_handle(HANDLE hProcess);
#else
// Add process to pool
void wm_append_sid(pid_t sid);

// Remove process group from pool
void wm_remove_sid(pid_t sid);
#endif

// Initialize children pool
void wm_children_pool_init();

// Terminate every child process group
void wm_kill_children();

// Reads an HTTP header and extracts the size of the response
long int wm_read_http_size(char *header);

// Reads an HTTP header and extracts an element from a regex
char* wm_read_http_header_element(char *header, char *regex);

/* Load or save the running state
 * op: WM_IO_READ | WM_IO_WRITE
 * Returns 0 if success, or 1 if fail.
 */
int wm_state_io(const char * tag, int op, void *state, size_t size);

// Frees the wmodule struct
void wm_free(wmodule * c);

// Send message to a queue with a specific delay
int wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) __attribute__((nonnull));

// Send message to a queue with a specific delay, and the option to stop the wait process.
int wm_sendmsg_ex(int usec, int queue, const char *message, const char *locmsg, char loc, bool (*fn_prd)()) __attribute__((nonnull));

// Check if a path is relative or absolute.
// Returns 0 if absolute, 1 if relative or -1 on error.
int wm_relative_path(const char * path);

/**
 Check the binary wich executes a commad has the specified hash.
 Returns:
     1 if the binary matchs with the specified digest, 0 if not.
    -1 if the binary doesn't exist.
    -2 invalid parameters.
*/
int wm_validate_command(const char *command, const char *digest, crypto_type ctype);

#ifndef WIN32
// Com request thread dispatcher
void * wmcom_main(void * arg);
/**
 * @brief Send a one-way message to wmodules
 *
 * @param message Payload.
 */
#endif
void wmcom_send(char * message);
size_t wmcom_dispatch(char * command, char ** output);
size_t wmcom_getconfig(const char * section, char ** output);
int wmcom_sync(char * buffer);

/**
 * @brief Find a module
 *
 * @param name Name of the module.
 * @return Pointer to a module structure.
 * @return NULL if the module was not found.
 */
wmodule * wm_find_module(const char * name);

/**
 * @brief Run a query in a module
 *
 * Run a command into a module structure, not in the same thread.
 * Query format: <module name> <command>
 *
 * @param query Command query
 * @param output Output payload
 * @return Size of the output
 */
size_t wm_module_query(char * query, char ** output);

#endif // W_MODULES
