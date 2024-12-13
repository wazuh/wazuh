/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 02, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_CTI_API_OFFSET_HPP
#define _UPDATE_CTI_API_OFFSET_HPP

#include "componentsHelper.hpp"
#include "sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/timeHelper.h"
#include <memory>

/**
 * @class UpdateCtiApiOffset
 *
 * @brief Class in charge of updating the content version as a step of a chain of responsibility.
 *
 */
class UpdateCtiApiOffset final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Update the content version.
     *
     * @param context updater context.
     */
    void update(const UpdaterContext& context) const
    {
        try
        {
            if (context.spUpdaterBaseContext->spRocksDB)
            {
                logDebug2(WM_CONTENTUPDATER, "Updating offset with value: '%d'", context.currentOffset);

                context.spUpdaterBaseContext->spRocksDB->put(Utils::getCompactTimestamp(std::time(nullptr)),
                                                             std::to_string(context.currentOffset),
                                                             Components::Columns::CURRENT_OFFSET);
            }
            else
            {
                throw std::runtime_error("RocksDB is not initialized");
            }
        }
        catch (const std::exception& e)
        {
            std::ostringstream errorMsg;
            errorMsg << "UpdateCtiApiOffset - Error updating the content version: " << e.what();
            throw std::runtime_error(errorMsg.str());
        }
    }

public:
    /**
     * @brief Update the content version.
     *
     * @param context updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "UpdateCtiApiOffset - Starting process");

        update(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _UPDATE_CTI_API_OFFSET_HPP
