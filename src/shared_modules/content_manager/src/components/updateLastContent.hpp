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

#ifndef _UPDATE_LAST_CONTENT_HPP
#define _UPDATE_LAST_CONTENT_HPP

#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>

/**
 * @class UpdateLastContent
 *
 * @brief Class in charge of updating the content version as a step of a chain of responsibility.
 *
 */
class UpdateLastContent final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Update the content version.
     *
     * @param context updater context.
     */
    void update(const UpdaterContext& context) const
    {
        // TODO implement behavior
        // 1. Get the database configuration from the context (context.spUpdaterBaseContext->configData.at("database"))
        // 2. Connect to the database
        // 3. Update the last content version processed
        std::ignore = context;
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

        update(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _UPDATE_LAST_CONTENT_HPP
