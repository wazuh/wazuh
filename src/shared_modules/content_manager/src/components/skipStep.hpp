/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 12, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SKIP_STEP_HPP
#define _SKIP_STEP_HPP

#include "../sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"

/**
 * @class SkipStep
 *
 * @brief Dummy step of a chain of responsibility. Used when a step is unnecessary (e.g. no decompressor).
 */
class SkipStep final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    std::vector<std::function<void(std::shared_ptr<UpdaterContext>)>> preActions;

public:
    /**
     * @brief Actions that take place in this step.
     *
     * @param action Function to be executed.
     */
    void registerPreAction(std::function<void(std::shared_ptr<UpdaterContext>)> const& action)
    {
        preActions.push_back(action);
    }

    /**
     * @brief Performs registered pre-actions and passes control to the next step of the chain.
     *
     * @param context updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "SkipStep - Starting process");

        for (auto const& action : preActions)
        {
            action(context);
        }

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _SKIP_STEP_HPP
