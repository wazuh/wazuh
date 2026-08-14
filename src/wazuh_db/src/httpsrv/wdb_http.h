/*
 * Wazuh Database Daemon
 * Copyright (C) 2015, Wazuh Inc.
 * August 12, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_HTTP_H
#define WDB_HTTP_H

#include "commonDefs.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Start the wazuh-db HTTP-over-Unix-socket API server.
     *
     * Registers the agent query/sync endpoints and starts listening on socket_path.
     *
     * @param callbackLog Log callback used to bridge the server's internal logging.
     * @param socket_path Path to the Unix domain socket, relative to the daemon's working directory.
     */
    void wdb_http_start(full_log_fnc_t callbackLog, const char* socket_path);

    /**
     * @brief Stop the wazuh-db HTTP-over-Unix-socket API server.
     */
    void wdb_http_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* WDB_HTTP_H */
