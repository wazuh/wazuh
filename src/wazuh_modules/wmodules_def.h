/*
 * Wazuh Module Manager
 * Copyright (C) 2015-2021, Wazuh Inc.
 * November 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef W_MODULES_DEFS
#define W_MODULES_DEFS

#include <pthread.h>
#include "cJSON.h"

#ifndef ARGV0
#define ARGV0 "wazuh-modulesd"
#endif // ARGV0

typedef void* (*wm_routine)(void*);     // Standard routine pointer

// Module context: this should be defined for every module

typedef struct wm_context {
    const char *name;                   // Name for module
    wm_routine start;                   // Main function
    wm_routine destroy;                 // Destructor
    cJSON *(* dump)(const void *);
    int (* sync)(const char*);          // Sync
} wm_context;

// Main module structure

typedef struct wmodule {
    pthread_t thread;                   // Thread ID
    const wm_context *context;          // Context (common structure)
    char *tag;                          // Module tag
    void *data;                         // Data (module-dependent structure)
    struct wmodule *next;               // Pointer to next module
} wmodule;

#endif //W_MODULES_DEFS
