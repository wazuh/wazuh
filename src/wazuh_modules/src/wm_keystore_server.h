/*
 * Wazuh Module for the keystore server (UDS at queue/sockets/keystore)
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WM_KEYSTORE_SERVER_H
#define _WM_KEYSTORE_SERVER_H

#define WM_KEYSTORE_SERVER_LOGTAG ARGV0 ":keystore-server"

#include "wmodules.h"

extern const wm_context WM_KEYSTORE_SERVER_CONTEXT;

/**
 * @brief The module carries NO configuration: the socket path is fixed (the Python framework's
 *        KeystoreClient hardcodes it) and there are no tunables. The struct exists because the
 *        wmodule machinery expects a data pointer to own.
 */
typedef struct wm_keystore_server_t
{
    int unused;
} wm_keystore_server_t;

wmodule* wm_keystore_server_read(void);

#endif /* _WM_KEYSTORE_SERVER_H */
