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

#include "indexer/IIndexerConnectorAsync.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "indexer/IIndexerSession.hpp"
#include "vd/IVdScanner.hpp"

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

    using IndexerSessionFactory =
        std::function<std::unique_ptr<invsync::indexer::IIndexerSession>(const nlohmann::json&, LoggingContext)>;
    using IndexerConnectorSyncFactory = std::function<std::unique_ptr<invsync::indexer::IIndexerConnectorSync>(
        const nlohmann::json&, const invsync::indexer::IIndexerSession&, LoggingContext)>;
    using IndexerConnectorAsyncFactory = std::function<std::unique_ptr<invsync::indexer::IIndexerConnectorAsync>(
        const nlohmann::json&, const invsync::indexer::IIndexerSession&, LoggingContext)>;
    using VdScannerFactory = std::function<std::shared_ptr<invsync::vd::IVdScanner>()>;

    /*
     * Override how each of the three indexer objects is constructed, so a test can drive the startup
     * gate deterministically without the real per-host health-check I/O (5 s timeout per host).
     *
     * Three separate setters: a gate test needs to fail exactly one of the three while leaving the
     * others healthy.
     */
    EXPORTED void setIndexerSessionFactoryForTests(IndexerSessionFactory factory);
    EXPORTED void setIndexerConnectorSyncFactoryForTests(IndexerConnectorSyncFactory factory);
    EXPORTED void setIndexerConnectorAsyncFactoryForTests(IndexerConnectorAsyncFactory factory);
    EXPORTED void setVdScannerFactoryForTests(VdScannerFactory factory);

    /// Forces one retry attempt synchronously instead of waiting out the real heartbeat.
    EXPORTED void forceRetryForTests();

    /// Runs one indexer-health poll synchronously, as the worker's heartbeat would.
    EXPORTED void pollIndexerHealthForTests();

} // namespace invsync::test_hooks

#endif // _INVENTORY_SYNC_SERVER_TEST_HOOKS_HPP
