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

/**
 * @class UpdateIndexerCursor
 *
 * @brief Persists the Indexer sync cursor (string representation of the integer offset
 *        field) to RocksDB after each successful fetch cycle.
 *
 * Replaces UpdateCtiApiOffset. Stores the highest offset seen as a string (e.g. "1042").
 * The cursor value is read from context.data["cursor"], which is set by IndexerDownloader
 * at the end of each initial-load or incremental-update run.
 *
 * On the next scheduler cycle ExecutionContext reads the stored value back via
 * getLastKeyValue(CURRENT_OFFSET), and IndexerDownloader interprets it as the
 * lower bound for the incremental range query.
 */
class UpdateIndexerCursor final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Write the cursor to RocksDB.
     *
     * @param context Updater context that must carry a valid spRocksDB and
     *                a "cursor" field inside context.data.
     */
    void update(const UpdaterContext& context) const
    {
        if (!context.spUpdaterBaseContext->spRocksDB)
        {
            throw std::runtime_error("UpdateIndexerCursor: RocksDB is not initialized");
        }

        if (!context.data.contains("cursor"))
        {
            logDebug2(WM_CONTENTUPDATER, "UpdateIndexerCursor: No cursor in context data, skipping persistence");
            return;
        }

        const auto cursor = context.data.at("cursor").get<std::string>();
        if (cursor.empty())
        {
            logDebug2(WM_CONTENTUPDATER, "UpdateIndexerCursor: Cursor is empty, skipping persistence");
            return;
        }

        logDebug2(WM_CONTENTUPDATER, "UpdateIndexerCursor: Persisting cursor '%s'", cursor.c_str());

        context.spUpdaterBaseContext->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)), cursor, Components::Columns::CURRENT_OFFSET);
    }

public:
    /**
     * @brief Persist the cursor and continue the chain.
     *
     * @param context Updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
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
