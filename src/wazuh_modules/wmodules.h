/*
 * Wazuh Module Manager
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 22, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef W_MODULES
#define W_MODULES

#ifndef ARGV0
#define ARGV0 "wazuh-modulesd"
#endif // ARGV0

#include "shared.h"
#include <pthread.h>
#include "config/config.h"

#define WM_DEFAULT_DIR  DEFAULTDIR "/wodles"        // Default modules directory.
#define WM_STATE_DIR    DEFAULTDIR "/var/wodles"    // Default directory for states.
#define WM_DIR_WIN      "wodles"                    // Default directory for states (Windows)
#define WM_STRING_MAX   67108864                    // Max. dynamic string size (64 MB).
#define WM_BUFFER_MAX   1024                        // Max. static buffer size.
#define WM_BUFFER_MIN   1024                        // Starting JSON buffer length.
#define WM_MAX_ATTEMPTS 3                           // Max. number of attempts.
#define WM_MAX_WAIT     1                           // Max. wait between attempts.
#define WM_IO_WRITE     0
#define WM_IO_READ      1
#define WM_ERROR_TIMEOUT 1                          // Error code for timeout.
#define WM_POOL_SIZE    8                           // Child process pool size.
#define WM_HEADER_SIZE  OS_SIZE_2048
#define VU_WM_NAME "vulnerability-detector"
#define AZ_WM_NAME "azure-logs"
#define KEY_WM_NAME "agent-key-polling"

#define WM_DEF_TIMEOUT      1800            // Default runtime limit (30 minutes)
#define WM_DEF_INTERVAL     86400           // Default cycle interval (1 day)

#define DAY_SEC    86400
#define WEEK_SEC   604800

#define EXECVE_ERROR 0x7F

typedef void* (*wm_routine)(void*);     // Standard routine pointer

// Module context: this should be defined for every module

typedef struct wm_context {
    const char *name;                   // Name for module
    wm_routine start;                   // Main function
    wm_routine destroy;                 // Destructor
    cJSON *(* dump)(const void *);
} wm_context;

// Main module structure

typedef struct wmodule {
    pthread_t thread;                   // Thread ID
    const wm_context *context;          // Context (common structure)
    char *tag;                          // Module tag
    void *data;                         // Data (module-dependent structure)
    struct wmodule *next;               // Pointer to next module
} wmodule;

// Verification type
typedef enum crypto_type {
    MD5SUM,
    SHA1SUM,
    SHA256SUM
} crypto_type;

// Inclusion of modules

#include "wm_oscap.h"
#include "wm_database.h"
#include "syscollector/syscollector.h"
#include "wm_command.h"
#include "wm_ciscat.h"
#include "wm_aws.h"
#include "wm_vuln_detector.h"
#include "wm_osquery_monitor.h"
#include "wm_download.h"
#include "wm_azure.h"
#include "wm_docker.h"
#include "wm_keyrequest.h"

extern wmodule *wmodules;       // Loaded modules.
extern int wm_task_nice;        // Nice value for tasks.
extern int wm_max_eps;          // Maximum events per second sent by OpenScap Wazuh Module
extern int wm_kill_timeout;     // Time for a process to quit before killing it
extern int wm_debug_level;

// Read XML configuration and internal options
int wm_config();
cJSON *getModulesConfig(void);
cJSON *getModulesInternalOptions(void);

// Add module to the global list
void wm_add(wmodule *module);

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

// Terminate every child process group
void wm_kill_children();

// Reads an HTTP header and extracts the size of the response
long int wm_read_http_size(char *header);

// Tokenize string separated by spaces, respecting double-quotes
char** wm_strtok(char *string);

/* Load or save the running state
 * op: WM_IO_READ | WM_IO_WRITE
 * Returns 0 if success, or 1 if fail.
 */
int wm_state_io(const char * tag, int op, void *state, size_t size);

// Frees the wmodule struct
void wm_free(wmodule * c);

// Send message to a queue with a specific delay
int wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) __attribute__((nonnull));

// Check if a path is relative or absolute.
// Returns 0 if absolute, 1 if relative or -1 on error.
int wm_relative_path(const char * path);

// Get time in seconds to the specified hour in hh:mm
int get_time_to_hour(const char * hour);

// Get time to reach a particular day of the week and hour
int get_time_to_day(int wday, const char * hour);

// Function to look for the correct day of the month to run a wodle
int check_day_to_scan(int day, const char *hour);

// Get binary full path
int wm_get_path(const char *binary, char **validated_comm);

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
#endif
size_t wmcom_dispatch(char * command, char ** output);
size_t wmcom_getconfig(const char * section, char ** output);

// Sleep function for Windows and Unix (milliseconds)
void wm_delay(unsigned int ms);

#endif // W_MODULES
