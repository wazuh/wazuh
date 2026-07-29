/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_SERVER_TEST_HOOKS_HPP
#define _INVENTORY_SYNC_SERVER_TEST_HOOKS_HPP

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "indexer/IIndexerConnector.hpp"

#include <indexerConnector.hpp>

#include <functional>
#include <json.hpp>
#include <memory>

namespace invsync::test_hooks
{

    /**
     * @brief TEST-ONLY entry points into InventorySyncServerFacade's own test hooks.
     *
     * These are plain, non-inline, EXPORTED functions defined in a .cpp compiled into this
     * module's .so, not inline methods a test calls directly on the facade. That distinction is
     * load-bearing: InventorySyncServerFacade is header-only, and its methods call LOGFN_* macros,
     * which need Log::GLOBAL_LOG_FUNCTION -- a hidden-visibility symbol only this .so itself can
     * resolve. Calling a facade method directly from a test .cpp would instantiate that inline
     * code INSIDE the test binary, which links against the .so but can never see that hidden
     * symbol -- an undefined reference at link time. Routing through an exported function defined
     * in a .cpp (this module's own translation unit) keeps all of that code where it can resolve,
     * exactly like the extern "C" inventory_sync_server_start()/_stop() shims already do.
     *
     * Never called in production; modulesd only ever calls inventory_sync_server_start()/_stop().
     */

    using IndexerConnectorFactory =
        std::function<std::unique_ptr<invsync::indexer::IIndexerConnector>(const nlohmann::json&, LoggingContext)>;

    /// Overrides how the indexer connector is constructed, so a test can gate/unblock the startup
    /// gate deterministically without IndexerConnectorSync's real per-host health-check I/O.
    EXPORTED void setIndexerConnectorFactoryForTests(IndexerConnectorFactory factory);

    /// Forces one retry attempt synchronously instead of waiting out the real heartbeat.
    EXPORTED void forceRetryForTests();

} // namespace invsync::test_hooks

#endif // _INVENTORY_SYNC_SERVER_TEST_HOOKS_HPP
