/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_INDEXER_CURSOR_HPP
#define _UPDATE_INDEXER_CURSOR_HPP

#include "componentsHelper.hpp"
#include "sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/timeHelper.h"
#include <memory>
#include <sstream>
#include <stdexcept>

class UpdateIndexerCursor final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    void update(const UpdaterContext& context) const
    {
        if (!context.spUpdaterBaseContext->spRocksDB)
        {
            throw std::runtime_error("UpdateIndexerCursor: RocksDB is not initialized");
        }

        if (!context.data.contains("cursor"))
        {
            return;
        }

        const auto cursor = context.data.at("cursor").get<std::string>();
        if (cursor.empty())
        {
            return;
        }

        context.spUpdaterBaseContext->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)), cursor, Components::Columns::CURRENT_OFFSET);
    }

public:
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "UpdateIndexerCursor - Starting process");

        try
        {
            update(*context);
        }
        catch (const std::exception& e)
        {
            std::ostringstream msg;
            msg << "UpdateIndexerCursor - Error persisting cursor: " << e.what();
            throw std::runtime_error(msg.str());
        }

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _UPDATE_INDEXER_CURSOR_HPP
