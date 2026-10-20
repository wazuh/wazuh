/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CONTENT_INDEXER_ADAPTERS_HPP
#define _CONTENT_INDEXER_ADAPTERS_HPP

#include "contentIndexer.hpp"
#include <memory>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

// Forward-declared, not included: indexerConnector.hpp is not on the include path this library's
// public headers are held to (content_manager_public_abi_c17), and a host that passes a connector
// already includes it.
class IndexerConnectorSync;
class IndexerConnectorAsync;

namespace content_manager
{
    /**
     * @brief Use a host's synchronous connector as the content manager's indexer.
     *
     * The adapter keeps the connector alive for as long as any registration holds it. Requests are
     * forwarded as-is: the connector logs its own failures, under the host's tag.
     *
     * @param connector The host's connector. Must not be null.
     * @return The indexer to pass to every `ContentRegister`.
     * @throws std::invalid_argument if @p connector is null.
     */
    EXPORTED std::shared_ptr<IContentIndexer> makeContentIndexer(std::shared_ptr<IndexerConnectorSync> connector);

    /**
     * @brief Use a host's asynchronous connector as the content manager's indexer.
     *
     * Only the connector's synchronous read operations are used; nothing goes through its indexing
     * queue, so a download does not delay the events the host is indexing.
     *
     * @param connector The host's connector. Must not be null.
     * @return The indexer to pass to every `ContentRegister`.
     * @throws std::invalid_argument if @p connector is null.
     */
    EXPORTED std::shared_ptr<IContentIndexer> makeContentIndexer(std::shared_ptr<IndexerConnectorAsync> connector);
} // namespace content_manager

#endif // _CONTENT_INDEXER_ADAPTERS_HPP
