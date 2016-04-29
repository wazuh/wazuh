/*
 * Wazuh Module Manager
 * Wazuh Inc.
 * April 22, 2016
 */

#ifndef W_MODULES
#define W_MODULES

#ifndef ARGV0
#define ARGV0 "wazuh-moduled"
#endif // ARGV0

#include "shared.h"
#include "config/config.h"

#define WM_STRING_MAX 1048576           // Max. dynamic string size.
#define WM_BUFFER_MAX 1024              // Max. static buffer size.

typedef void (*wm_routine)(void*);      // Standard routine pointer

// Module context: this should be defined for every module

typedef struct wm_context {
    const char *name;                   // Name for module
    wm_routine main;                    // Main function
    wm_routine destroy;                 // Destructor
} wm_context;

// Main module structure

typedef struct wmodule {
    const wm_context *context;          // Context (module-dependant)
    void *data;                         // Data (module-dependent)
    struct wmodule *next;               // Pointer to next module
} wmodule;

// Inclusion of modules

#include "wm_oscap.h"

extern wmodule *wmodules;               // Loaded modules.
extern int wm_flag_reload;              // Flag to reload configuration.

// Check general configuration
void wm_check();

// Destroy configuration data
void wm_destroy();

/* Execute command with timeout of secs. Status can be NULL.
 *
 * argv is a string array that must finish with NULL
 * Returns dynamic string. Caller is responsible for freeing it!
 * On error, returns NULL, and status may be defined or not.
 */
char* wm_exec(char* const *argv, int *status, int secs);

// Check whether the last execution timed out
int wm_exec_timeout();

/* Concatenate strings with optional separator
 *
 * str1 must be a valid pointer to NULL or a string at heap
 * Returns 0 if success, or -1 if fail.
 */
int wm_strcat(char **str1, const char *str2, char sep);

// Trim whitespaces from string
char* wm_strtrim(char *string);

#endif // W_MODULES
