/*
 * OS CA bundle discovery
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Deliberately dependency-free (plain POSIX stat(), no shared.h): the
 * https_client C++ module compiles this file directly rather than linking all
 * of libwazuh, so it must not pull in anything beyond libc. */
#include "os_cert_bundle.h"

#ifndef WIN32

#include <stddef.h>
#include <sys/stat.h>

/*
 * These values were taken from how libcurl looks for the paths at compilation time,
 * here it is modified to be able to support the precompiled deps.
 *
 * https://github.com/curl/curl/blob/5930cb1c465ef5f0de6f1b91a843bb6f0bed1f23/acinclude.m4#L2182
 */
const char* os_ca_bundle_candidates[] = {
    "/etc/ssl/certs/ca-certificates.crt",       // Debian systems
    "/etc/pki/tls/certs/ca-bundle.crt",         // Redhat and Mandriva
    "/usr/share/ssl/certs/ca-bundle.crt",       // RedHat
    "/usr/local/share/certs/ca-root-nss.crt",   // FreeBSD
    "/etc/ssl/cert.pem",                        // OpenBSD, FreeBSD, MacOS
    NULL
};

const char* os_find_ca_bundle(const char* const* candidates) {
    const char* const* list = candidates ? candidates : os_ca_bundle_candidates;
    struct stat st;

    for (size_t i = 0; list[i] != NULL; ++i) {
        if (stat(list[i], &st) == 0) {
            return list[i];
        }
    }

    return NULL;
}

#endif // !WIN32
