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

#include "contentExport.hpp"
#include "contentIndexer.hpp"
#include <chrono>
#include <memory>

// Forward-declared, not included: indexerConnector.hpp is not on the include path this library's
// public headers are held to (content_manager_public_abi_c17), and a host that passes a connector
// already includes it.
class IndexerConnectorSync;
class IndexerConnectorAsync;

namespace indexer_client
{
    class IClient;
} // namespace indexer_client

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

    /// Time budgets of the indexer_client adapter's calls (I159b).
    struct ContentIndexerOptions
    {
        /// Whole openPit/search call. Above the client's request timeout (60 s by default), so a hung attempt can
        /// time out, mark its node and still be retried on another one inside the call.
        std::chrono::milliseconds callDeadline {120000};
        /// One page (QueryOptions::pageDeadline), from its first attempt.
        std::chrono::milliseconds pageDeadline {90000};
        /// The pre-flight searchIndex probe, and any call while no indexer node is usable (I158b).
        std::chrono::milliseconds probeDeadline {10000};
    };

    /**
     * @brief Use a host's indexer_client Client as the content manager's indexer (I154).
     *
     * The adapter keeps the Client alive for as long as any registration holds it, and so keeps the host's consumer
     * name reserved. PITs are managed by the library: a page retried after a transient failure reuses the same PIT
     * and cursor, and a released PIT is deleted in the background. While no indexer node is usable a call waits at
     * most `probeDeadline` for one, without sending anything (I158b); failures are thrown with the library's cause.
     *
     * The host's obligations: call requestClose() on its Client before it stops its content registrations, so a
     * call in flight returns at once instead of at its deadline; and drop every registration before creating a new
     * Client with the same consumer name.
     *
     * @param client The host's Client. Must not be null, and must hand out a query handle.
     * @param options Time budgets of the calls.
     * @return The indexer to pass to every `ContentRegister`.
     * @throws std::invalid_argument if @p client is null, its query() is null (a closed Client) or a deadline of
     *         @p options is not positive.
     */
    EXPORTED std::shared_ptr<IContentIndexer> makeContentIndexer(std::shared_ptr<indexer_client::IClient> client,
                                                                 ContentIndexerOptions options = {});
} // namespace content_manager

#endif // _CONTENT_INDEXER_ADAPTERS_HPP
