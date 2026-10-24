/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_FACTORIES_HPP
#define _INVSYNC_INDEXER_FACTORIES_HPP

#include "IIndexerConnectorSync.hpp"
#include "indexerClientSyncAdapter.hpp"

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace invsync::indexer
{

    /**
     * @brief Builds the module's Client, with its `inventory` and `agent-state` buckets, on the process runtime (I130,
     *        I144, I148).
     *
     * `runtime` is the opaque `const indexer_client::RuntimeRef*` modulesd publishes in the C config
     * (`indexer_runtime`). The production factory throws when it is null or when RuntimeRef::client()
     * refuses: that failure is the sync stage of the startup gate (I131). A test installs one that
     * returns a stand-in, so the gate's other stages keep their own fakes.
     */
    using IndexerClientFactory = std::function<std::shared_ptr<indexer_client::IClient>(
        const void* runtime, const std::vector<indexer_client::BucketSpec>& buckets)>;

    /// Builds one worker's sync connector over the shared Client (I144).
    using IndexerConnectorSyncFactory =
        std::function<std::unique_ptr<IIndexerConnectorSync>(std::shared_ptr<indexer_client::IClient> client,
                                                             const AdapterOptions& options,
                                                             std::shared_ptr<const std::atomic<bool>> closing,
                                                             const std::string& tag)>;

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_FACTORIES_HPP
