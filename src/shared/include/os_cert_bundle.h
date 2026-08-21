/*
 * OS CA bundle discovery
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_CERT_BUNDLE_H
#define OS_CERT_BUNDLE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32

/**
 * @brief Well-known OS CA bundle locations, probed in priority order by
 *        os_find_ca_bundle()'s default (candidates == NULL) behavior.
 */
extern const char* os_ca_bundle_candidates[];

/**
 * @brief Return the first candidate CA bundle path that exists on this host.
 *
 * The dependency (curl/OpenSSL) is precompiled, so the bundle path it was built
 * against may not exist on the host it actually runs on; this looks the file up
 * at run time instead of trusting the compiled-in default.
 *
 * @param candidates NULL-terminated array of paths to probe, in priority order.
 *        Pass NULL to probe the built-in os_ca_bundle_candidates list (the real
 *        production behavior); a test may pass its own list to point the probe
 *        at a temporary file.
 * @return The first candidate that exists on disk, or NULL if none do. Points
 *         into `candidates` (or the built-in list); never allocated, never
 *         owned by the caller.
 */
const char* os_find_ca_bundle(const char* const* candidates);

#endif // !WIN32

#ifdef __cplusplus
}
#endif

#endif // OS_CERT_BUNDLE_H
