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

#include "flatbuffers/include/inventorySync_generated.h"

namespace invsync::schema
{

    /**
     * The single place that names the generated FlatBuffers namespace. All server code refers to the
     * schema as `invsync::schema::fb::...`. Since the FullSession contract replaced the legacy
     * session-based schema as the single shared inventorySync.fbs, this aliases the shared
     * Wazuh.SyncSchema namespace directly -- the transitional own-copy schema (Wazuh.SyncSchemaServer,
     * which existed to dodge cross-DSO ODR clashes with the legacy headers) is gone.
     */
    namespace fb = Wazuh::SyncSchema;

} // namespace invsync::schema

#endif // _INVSYNC_SCHEMA_SYNC_SCHEMA_HPP
