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

#include "inventorySyncServerTestHooks.hpp"

#include "inventorySyncServerFacade.hpp"

#include <utility>

namespace invsync::test_hooks
{

    void setIndexerSessionFactoryForTests(IndexerSessionFactory factory)
    {
        invsync::InventorySyncServerFacade::instance().setIndexerSessionFactoryForTests(std::move(factory));
    }

    void setIndexerConnectorSyncFactoryForTests(IndexerConnectorSyncFactory factory)
    {
        invsync::InventorySyncServerFacade::instance().setIndexerConnectorSyncFactoryForTests(std::move(factory));
    }

    void setIndexerConnectorAsyncFactoryForTests(IndexerConnectorAsyncFactory factory)
    {
        invsync::InventorySyncServerFacade::instance().setIndexerConnectorAsyncFactoryForTests(std::move(factory));
    }

    void setVdScannerFactoryForTests(VdScannerFactory factory)
    {
        invsync::InventorySyncServerFacade::instance().setVdScannerFactoryForTests(std::move(factory));
    }

    void forceRetryForTests()
    {
        invsync::InventorySyncServerFacade::instance().forceRetryForTests();
    }

    void pollIndexerHealthForTests()
    {
        invsync::InventorySyncServerFacade::instance().pollIndexerHealthForTests();
    }

} // namespace invsync::test_hooks
