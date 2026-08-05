/* Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Stubs for the https_client module C-ABI (client-agent/https_client/include/
 * https_client.h). The agentd bridge (https_client_bridge.c) calls these, but
 * the client-agent unit test binaries do not link the real libhttps_client, so
 * without these stubs any test that pulls the bridge object fails to link.
 *
 * These are never meaningfully exercised: tests that assert on the bridge's use
 * of the module intercept the calls with --wrap (so the real symbol is unused).
 * Handles are opaque here; the linker resolves by name.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void *hc_create(const void *config, const void *callbacks)
{
    (void)config;
    (void)callbacks;
    return NULL;
}

bool hc_start(void *handle)
{
    (void)handle;
    return false;
}

void hc_stop(void *handle)
{
    (void)handle;
}

void hc_destroy(void *handle)
{
    (void)handle;
}

bool hc_submit_event(void *handle, const uint8_t *frame, size_t length)
{
    (void)handle;
    (void)frame;
    (void)length;
    return false;
}

bool hc_submit_sync_session(void *handle, const char *session_id, const uint8_t *buffer, size_t length)
{
    (void)handle;
    (void)session_id;
    (void)buffer;
    (void)length;
    return false;
}

void hc_notify_now(void *handle)
{
    (void)handle;
}

bool hc_set_config_hash(void *handle, const char *config_hash)
{
    (void)handle;
    (void)config_hash;
    return false;
}

bool hc_set_agent_key(void *handle, const char *key_hex)
{
    (void)handle;
    (void)key_hex;
    return false;
}

int hc_get_state(const void *handle)
{
    (void)handle;
    return 0;
}
