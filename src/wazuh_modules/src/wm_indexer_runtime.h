/*
 * Wazuh Module Manager - indexer client runtime
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_INDEXER_RUNTIME_H
#define WM_INDEXER_RUNTIME_H

#include <stdbool.h>
#include <cJSON.h>

/*
 * modulesd's side of the process-wide indexer_client runtime. Manager only: on the agent every function
 * is a no-op. The C++ owner lives in libwm_indexer_runtime.so, loaded at run time.
 *
 * wm_indexer_runtime_configure() runs in wm_config(), before the fork. Without a consumer it does nothing (no library
 * is loaded and no option is read or validated). With one, it loads the library, reads the internal-options file
 * (WAZUH_LDEFINES; absent => defaults silently, unreadable => ERROR with the path and defaults) and validates the
 * wazuh_modules.indexer_client_* family against the <indexer> section. Returns -1 (after logging why) when the library
 * cannot be loaded or the configuration is invalid: wm_config() fails, so do "wazuh-modulesd -t" and the start.
 *
 * The rest runs on the main thread only (the runtime's owner thread): start after the startup gate and before
 * the module threads (-1 => logged, modulesd goes on without a runtime), begin_shutdown/shutdown from
 * wm_shutdown_run() and wm_cleanup(). wm_indexer_runtime_ref() is the opaque RuntimeRef* for consumers, NULL
 * without a runtime.
 */
int wm_indexer_runtime_configure(const cJSON *indexer, bool has_consumer);
int wm_indexer_runtime_start(void);
const void *wm_indexer_runtime_ref(void);
void wm_indexer_runtime_begin_shutdown(long remaining_ms);
void wm_indexer_runtime_shutdown(void);

#endif /* WM_INDEXER_RUNTIME_H */
