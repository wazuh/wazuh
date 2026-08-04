/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_SCHEMA_SYNC_SCHEMA_HPP
#define _INVSYNC_SCHEMA_SYNC_SCHEMA_HPP

#include <inventorySyncSession_generated.h>

namespace invsync::schema
{

    /**
     * The single place that names the generated FlatBuffers namespace. All server code refers to the
     * schema as `invsync::schema::fb::...` so that when the legacy inventorySync schema is retired and
     * this one becomes the shared inventorySync.fbs (back under Wazuh.SyncSchema), only this alias
     * changes. The rationale for the temporary namespace lives in schemas/inventorySyncSession.fbs.
     */
    namespace fb = Wazuh::SyncSchemaServer;

} // namespace invsync::schema

#endif // _INVSYNC_SCHEMA_SYNC_SCHEMA_HPP
