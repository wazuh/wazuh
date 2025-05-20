/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_ORCHESTRATOR_HPP
#define _FACTORY_ORCHESTRATOR_HPP

#include "base/utils/chainOfResponsability.hpp"
#include "osScanner.hpp"
#include "packageScanner.hpp"
#include "responseBuilder.hpp"
#include "scanContext.hpp"
#include <databaseFeedManager.hpp>
#include <memory>
/**
 * @brief FactoryOrchestrator class.
 *
 */
template<typename TPackageScanner = PackageScanner,
         typename TOsScanner = OsScanner,
         typename TResponseBuilder = ResponseBuilder,
         typename TScanContext = ScanContext,
         typename TDatabaseFeedManager = DatabaseFeedManager>
class TFactoryOrchestrator final
{
private:
    TFactoryOrchestrator() = default;

public:
    /**
     * @brief Creates an orchestrator and returns it.
     *
     * @param type Scanner type.
     * @param databaseFeedManager DatabaseFeedManager object.
     * @return std::shared_ptr<TScanContext> Abstract handler.
     */
    static std::shared_ptr<utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>>
    create(const ScannerType type, std::shared_ptr<TDatabaseFeedManager> databaseFeedManager)
    {
        std::shared_ptr<utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>> orchestration;
        switch (type)
        {
            case ScannerType::Package:
                orchestration = std::make_shared<TPackageScanner>(databaseFeedManager);
                orchestration->setLast(std::make_shared<TResponseBuilder>(databaseFeedManager));
                break;

            case ScannerType::Os:
                orchestration = std::make_shared<TOsScanner>(databaseFeedManager);
                orchestration->setLast(std::make_shared<TResponseBuilder>(databaseFeedManager));
                break;

            default: throw std::invalid_argument("Invalid scanner type");
        }

        return orchestration;
    }
};

using FactoryOrchestrator = TFactoryOrchestrator<>;

#endif // _FACTORY_ORCHESTRATOR_HPP
