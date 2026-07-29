/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP
#define _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP

#include "indexer/IIndexerConnector.hpp"
#include "indexer/indexerConnectorAdapter.hpp"
#include "inventorySyncServerTestHooks.hpp"

#include <atomic>
#include <memory>
#include <utility>

namespace invsync::test
{

    /// A trivially-successful IIndexerConnector: never throws to construct, always available.
    /// Optionally reports its own destruction, so a test can pin the facade's teardown order.
    class FakeIndexerConnector final : public invsync::indexer::IIndexerConnector
    {
    public:
        explicit FakeIndexerConnector(std::shared_ptr<std::atomic<int>> destructions = nullptr)
            : m_destructions {std::move(destructions)}
        {
        }

        ~FakeIndexerConnector() override
        {
            if (m_destructions)
            {
                m_destructions->fetch_add(1);
            }
        }

        bool isAvailable() const override
        {
            return true;
        }

    private:
        std::shared_ptr<std::atomic<int>> m_destructions;
    };

    /**
     * @brief Installs a factory that always succeeds instantly, bypassing IndexerConnectorSync's
     *        real (synchronous, network-bound) construction entirely.
     *
     * @param destructions Optional shared counter, incremented when the fake is destroyed --
     *                     lets a test pin stop()'s teardown.
     * @return A shared counter of how many times the factory was actually invoked, so a test can
     *         assert a successful construction is never repeated across retries.
     */
    inline std::shared_ptr<std::atomic<int>>
    installAlwaysAvailableFakeIndexer(std::shared_ptr<std::atomic<int>> destructions = nullptr)
    {
        auto constructions = std::make_shared<std::atomic<int>>(0);
        invsync::test_hooks::setIndexerConnectorFactoryForTests(
            [constructions, destructions](const nlohmann::json&, LoggingContext)
            {
                constructions->fetch_add(1);
                return std::make_unique<FakeIndexerConnector>(destructions);
            });
        return constructions;
    }

    /// Restores the real, production factory (constructs a real IndexerConnectorSync). Call this
    /// from TearDown() so an override made by one test can never leak into the next.
    inline void resetIndexerConnectorFactoryToProduction()
    {
        invsync::test_hooks::setIndexerConnectorFactoryForTests(
            [](const nlohmann::json& config, LoggingContext logging)
            { return std::make_unique<invsync::indexer::IndexerConnectorAdapter>(config, std::move(logging)); });
    }

} // namespace invsync::test

#endif // _INVSYNC_TEST_INDEXER_CONNECTOR_FAKES_HPP
