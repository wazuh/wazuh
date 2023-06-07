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

#ifndef _PUB_SUB_PUBLISHER_HPP
#define _PUB_SUB_PUBLISHER_HPP

#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <iostream>
#include <memory>

/**
 * @class PubSubPublisher
 *
 * @brief Class in charge of publishing the content as a step of a chain of responsibility.
 *
 */
class PubSubPublisher final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Publish the content.
     *
     * @param context updater context.
     */
    void publish(const UpdaterContext& context) const
    {
        // If there is data to publish, send it
        if (!context.data.empty())
        {
            context.spUpdaterBaseContext->spChannel->send(context.data);
            std::cout << "PubSubPublisher - Data published" << std::endl;
        }
        else
        {
            std::cout << "PubSubPublisher - No data data to publish" << std::endl;
        }
    }

public:
    /**
     * @brief Publish the content.
     *
     * @param context updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {

        publish(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _PUB_SUB_PUBLISHER_HPP
