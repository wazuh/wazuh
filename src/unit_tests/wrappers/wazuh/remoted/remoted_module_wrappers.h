/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef REMOTED_MODULE_WRAPPERS_H
#define REMOTED_MODULE_WRAPPERS_H

#include <stddef.h> // size_t

// Forward declarations to avoid including remoted_module.h
typedef void (*logging_callback_t)(int level, const char* message);
typedef struct remoted_module_config_t remoted_module_config_t;

void __wrap_remoted_module_start(const logging_callback_t logCb, const remoted_module_config_t* config);

void __wrap_remoted_module_stop(void);

/**
 * @brief Mock of the CA-signs-leaf accessor the legacy task poller consults before sending a CA.
 *
 * Unlike the two above, this one HAS a return value the caller branches on, so it is driven by
 * mock_type(): a test that exercises the CA path must will_return() 1, 0 or -1 for every call it
 * expects. Defaults are deliberately absent -- an unset expectation should fail the test loudly
 * rather than silently pick a branch.
 */
int __wrap_remoted_module_tls_ca_matches_leaf(void);

/**
 * @brief Mock of the export that hands the legacy task poller the ONE CA certificate to deliver.
 *
 * Driven by TWO queued values, in this order: the PEM to copy into @p buffer (or NULL to copy
 * nothing), then the int to return. That split is what lets a test drive the three outcomes the
 * caller branches on without inventing bytes for the ones that have none: a positive length WITH a
 * PEM (delivery), 0 with NULL (nothing signs the served certificate, or no bundle) and -1 with NULL
 * (the certificate does not fit the caller's buffer).
 *
 * At most @p capacity bytes are copied, and never the NUL terminator: the real export reports a
 * length and leaves termination to the caller, so a mock that terminated the buffer itself would
 * hide a caller that forgot to.
 */
int __wrap_remoted_module_tls_leaf_signer_pem(char* buffer, size_t capacity);

#endif
