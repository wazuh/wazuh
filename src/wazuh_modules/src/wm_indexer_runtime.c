/*
 * Wazuh Module Manager - indexer client runtime
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_indexer_runtime.h"

/* The body stays under #ifndef CLIENT: the agent's source glob picks this file up too (wazuh_modules/CMakeLists.txt). */

#ifndef CLIENT

#include "wmodules.h"
#include "sym_load.h"
/* Only the C typedefs of the library's API; modulesd never links it (I132). */
#include "wm_indexer_runtime_api.h"
#ifdef __linux__
#include <dlfcn.h>
#endif

#define WM_INDEXER_RUNTIME_LOGTAG ARGV0 ":indexer-client"
#define WM_INDEXER_RUNTIME_REASON_LEN 1024

typedef int (*wmir_configure_fn)(const char *, const char *, int, char *, size_t);
typedef int (*wmir_start_fn)(wmir_log_fn, char *, size_t);
typedef const void *(*wmir_ref_fn)(void);
typedef void (*wmir_begin_shutdown_fn)(long);
typedef void (*wmir_shutdown_fn)(void);

static void *wm_indexer_runtime_module = NULL;
static wmir_configure_fn wmir_configure_ptr = NULL;
static wmir_start_fn wmir_start_ptr = NULL;
static wmir_ref_fn wmir_ref_ptr = NULL;
static wmir_begin_shutdown_fn wmir_begin_shutdown_ptr = NULL;
static wmir_shutdown_fn wmir_shutdown_ptr = NULL;

/* Loads libwm_indexer_runtime.so and its five symbols once (I132). Returns 0, or -1 after logging what is missing. */
static int wm_indexer_runtime_load(void)
{
    void *handle;
    void *symbols[5];
    static const char *const names[5] = {
        "wmir_configure", "wmir_start", "wmir_ref", "wmir_begin_shutdown", "wmir_shutdown"
    };
    size_t i;

    if (wm_indexer_runtime_module) {
        return 0;
    }

    if (handle = so_get_module_handle("wm_indexer_runtime"), !handle) {
        const char *cause = NULL;
#ifdef __linux__
        /* so_get_module_handle() is dlopen(): its error names the missing file or the unresolved symbol. */
        cause = dlerror();
#endif
        mterror(WM_INDEXER_RUNTIME_LOGTAG, "Unable to load libwm_indexer_runtime.so (%s); the installation is broken.",
                cause ? cause : "unknown cause");
        return -1;
    }

    for (i = 0; i < 5; i++) {
        if (symbols[i] = so_get_function_sym(handle, names[i]), !symbols[i]) {
            mterror(WM_INDEXER_RUNTIME_LOGTAG, "libwm_indexer_runtime.so does not export %s; the installation is broken.", names[i]);
            so_free_library(handle);
            return -1;
        }
    }

    wmir_configure_ptr = (wmir_configure_fn)symbols[0];
    wmir_start_ptr = (wmir_start_fn)symbols[1];
    wmir_ref_ptr = (wmir_ref_fn)symbols[2];
    wmir_begin_shutdown_ptr = (wmir_begin_shutdown_fn)symbols[3];
    wmir_shutdown_ptr = (wmir_shutdown_fn)symbols[4];
    wm_indexer_runtime_module = handle;
    return 0;
}

/* Whole internal-options file. Absent => empty text, silently; unreadable => ERROR with the path and empty text (I133). */
static char *wm_indexer_runtime_read_options(void)
{
    const char *path = WAZUH_LDEFINES;
    char *text = NULL;
    size_t size = 0;
    size_t capacity = 4096;
    size_t n;
    FILE *fp;

    os_calloc(capacity, sizeof(char), text);

    if (fp = wfopen(path, "r"), !fp) {
        if (errno != ENOENT) {
            mterror(WM_INDEXER_RUNTIME_LOGTAG, FOPEN_ERROR, path, errno, strerror(errno));
        }
        return text;
    }

    while (n = fread(text + size, 1, capacity - size - 1, fp), n > 0) {
        size += n;
        if (capacity - size - 1 == 0) {
            capacity *= 2;
            os_realloc(text, capacity, text);
        }
    }

    if (ferror(fp)) {
        mterror(WM_INDEXER_RUNTIME_LOGTAG, FREAD_ERROR, path, errno, strerror(errno));
        size = 0;
    }

    text[size] = '\0';
    fclose(fp);
    return text;
}

int wm_indexer_runtime_configure(const cJSON *indexer, bool has_consumer)
{
    char reason[WM_INDEXER_RUNTIME_REASON_LEN] = "";
    char *options_text;
    char *indexer_json;
    int result;

    if (!has_consumer) {
        return 0;
    }

    if (wm_indexer_runtime_load() != 0) {
        return -1;
    }

    options_text = wm_indexer_runtime_read_options();
    indexer_json = indexer ? cJSON_PrintUnformatted(indexer) : NULL;

    result = wmir_configure_ptr(options_text, indexer_json ? indexer_json : "{}", 1, reason, sizeof(reason));

    if (result != 0) {
        mterror(WM_INDEXER_RUNTIME_LOGTAG, "Invalid indexer client configuration: %s", reason);
        result = -1;
    }

    os_free(indexer_json);
    os_free(options_text);
    return result;
}

int wm_indexer_runtime_start(void)
{
    char reason[WM_INDEXER_RUNTIME_REASON_LEN] = "";

    if (!wm_indexer_runtime_module) {
        return 0;
    }

    if (wmir_start_ptr(mtLoggingFunctionsWrapper, reason, sizeof(reason)) != 0) {
        mterror(WM_INDEXER_RUNTIME_LOGTAG,
                "The indexer client runtime did not start: %s. Modules that use it run without it until modulesd "
                "restarts.",
                reason);
        return -1;
    }

    if (wmir_ref_ptr() != NULL) {
        mtinfo(WM_INDEXER_RUNTIME_LOGTAG, "Indexer client runtime started.");
    }

    return 0;
}

const void *wm_indexer_runtime_ref(void)
{
    return wm_indexer_runtime_module ? wmir_ref_ptr() : NULL;
}

void wm_indexer_runtime_begin_shutdown(long remaining_ms)
{
    if (wm_indexer_runtime_module) {
        wmir_begin_shutdown_ptr(remaining_ms);
    }
}

void wm_indexer_runtime_shutdown(void)
{
    if (wm_indexer_runtime_module) {
        wmir_shutdown_ptr();
    }
}

#else

int wm_indexer_runtime_configure(const cJSON *indexer, bool has_consumer)
{
    (void)indexer;
    (void)has_consumer;
    return 0;
}

int wm_indexer_runtime_start(void)
{
    return 0;
}

const void *wm_indexer_runtime_ref(void)
{
    return NULL;
}

void wm_indexer_runtime_begin_shutdown(long remaining_ms)
{
    (void)remaining_ms;
}

void wm_indexer_runtime_shutdown(void)
{
}

#endif /* CLIENT */
