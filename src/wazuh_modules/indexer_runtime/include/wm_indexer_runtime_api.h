/*
 * Wazuh modulesd indexer client runtime bridge
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WM_INDEXER_RUNTIME_API_H
#define _WM_INDEXER_RUNTIME_API_H

/*
 * C API of libwm_indexer_runtime.so: modulesd's owner of the process-wide indexer_client runtime (plan 18, E7a,
 * I128-I133). modulesd loads it at run time (so_get_module_handle, I132) and never links C++.
 *
 * Threading: wmir_configure() runs once in wm_config(), before the fork; wmir_start(), wmir_begin_shutdown() and
 * wmir_shutdown() run on modulesd's main thread only (the runtime's owner thread, I37). wmir_ref() may be called from
 * any thread. No function throws: every C++ exception is caught at this boundary and reported as -1 / no-op; the
 * functions without a reason buffer log one ERROR through the function wmir_start() received (nothing before it).
 * Failure reasons are written to the caller's buffer (NUL-terminated, truncated) and never carry the password.
 */

#include <stdarg.h>
#include <stddef.h>

/* The library is built with -fvisibility=hidden: these five functions are its only exports (G-diff E7a, obj. 9). */
#if defined(__GNUC__) || defined(__clang__)
#define WMIR_API __attribute__((visibility("default")))
#else
#define WMIR_API
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    /** Same shape as modulesd's mtLoggingFunctionsWrapper and indexer_client::LogFunction. */
    typedef void (*wmir_log_fn)(
        int level, const char* tag, const char* file, int line, const char* func, const char* msg, va_list args);

    /**
     * Validates the runtime configuration and keeps it for wmir_start(). options_text is the whole internal-options
     * file (empty when absent or unreadable, I133); indexer_json is the <indexer> section as JSON ("{}" when none).
     * Without a consumer (has_consumer == 0) nothing is validated or kept and the call returns 0.
     * Returns 0, or -1 with the reason (it names the offending key).
     */
    WMIR_API int wmir_configure(
        const char* options_text, const char* indexer_json, int has_consumer, char* reason, size_t reason_len);

    /**
     * Installs the library log function, reads the indexer credentials from the keystore and starts the runtime
     * (I128). Returns 0 when started or when nothing was configured; -1 with the reason otherwise (I131: modulesd goes
     * on without a runtime). A second call while running returns -1 and leaves the running runtime intact.
     */
    WMIR_API int wmir_start(wmir_log_fn log, char* reason, size_t reason_len);

    /**
     * The running runtime as an opaque indexer_client::RuntimeRef* (I130), or NULL when none runs. The pointed-to
     * object is allocated once and never freed: after wmir_shutdown() it stays readable and reports !valid().
     */
    WMIR_API const void* wmir_ref(void);

    /** Fixes the single shutdown deadline, remaining_ms from now (I129). No-op without a runtime. */
    WMIR_API void wmir_begin_shutdown(long remaining_ms);

    /** Joins the runtime threads (RuntimeOwner::shutdown). No-op without a runtime; a second call is a no-op. */
    WMIR_API void wmir_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif // _WM_INDEXER_RUNTIME_API_H
