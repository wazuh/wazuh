/* Durable VD feed offset registry client (agentd side)
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef VD_OFFSET_CLIENT_H
#define VD_OFFSET_CLIENT_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Observe a VD feed offset reported by the manager against the durable
 *        registry owned by the agent-info module (`vd_feed_state` table).
 *
 * On Linux/macOS, agent-info lives in a separate process (wazuh-modulesd), so
 * this is a local IPC round trip over the existing wmcom request socket
 * (WM_LOCAL_SOCK, "query agent-info {...}") -- no new socket, same generic
 * per-module query verb task_registry_client.c already uses. On Windows,
 * agent-info runs in the same process as agentd, so this calls straight into
 * wm_module_query_json_ex() in-process.
 *
 * Fails closed in the sense that mirrors task_registry_client: a registry
 * error reports out_changed=false, out_pending=false, never inventing a
 * re-scan request or an offset advance out of thin air.
 *
 * @param offset The offset value received from the manager.
 * @param out_changed Set to true if the offset advanced.
 * @param out_pending Set to true if a /scan/vd request is now outstanding.
 * @param out_pending_offset Set to the offset a pending request refers to
 *        (valid only when *out_pending is true).
 * @return true if the registry was reached and answered (regardless of
 *         changed/pending values); false on any error (unreachable,
 *         malformed/missing response, timeout).
 */
bool vd_offset_client_observe(uint64_t offset, bool *out_changed, bool *out_pending,
                              uint64_t *out_pending_offset);

/**
 * @brief Clear the pending VD re-scan flag, but only if it is still pending
 *        for exactly this offset (a stale confirmation is a no-op). Call
 *        only after a /scan/vd request for `offset` returns 200 OK.
 *
 * @param offset The offset the /scan/vd request succeeded for.
 * @return true if the pending flag was actually cleared; false otherwise
 *         (stale / nothing pending / registry unreachable).
 */
bool vd_offset_client_clear_pending(uint64_t offset);

#endif /* VD_OFFSET_CLIENT_H */
