/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_CERT_BUNDLE_WRAPPERS_H
#define OS_CERT_BUNDLE_WRAPPERS_H

const char* __wrap_os_find_ca_bundle(const char* const* candidates);

/// Convenience: arrange for the next os_find_ca_bundle() call to return `path`
/// (pass NULL to simulate "no OS CA bundle found").
void expect_os_find_ca_bundle(const char *path);

#endif
