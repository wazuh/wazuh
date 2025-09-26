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

#include "pubSubPublisherExceptions.hpp"
#include "sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
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
    void publish(UpdaterContext& context) const
    {
        // If there is data to publish, send it
        if (context.data.contains("paths") && !context.data.at("paths").empty())
        {
            // serialize the JSON object
            const auto message = context.data.dump();

            logDebug2(WM_CONTENTUPDATER, "Data to be published: '%s'", message.c_str());

            const auto [offset, hash, status] = context.spUpdaterBaseContext->fileProcessingCallback(
                message, context.spUpdaterBaseContext->spStopCondition);

            // Check if the operation was successful
            if (!status)
            {
                logDebug2(WM_CONTENTUPDATER, "Failed to publish data");

                // If we were processing offsets and it failed, we need to trigger a snapshot to recover
                if (context.data.at("type") == "offsets")
                {
                    throw OffsetProcessingException {"Failed to process offsets"};
                }

                // If we were processing a snapshot and it failed, we need to stop the process
                throw SnapshotProcessingException {"Failed to process the snapshot"};
            }

            // Update the offset and hash
            context.currentOffset = offset;
            context.spUpdaterBaseContext->downloadedFileHash = hash;
            logDebug2(WM_CONTENTUPDATER, "Data published. Offset: '%d', Hash: '%s'", offset, hash.c_str());
        }
        else
        {
            logDebug2(WM_CONTENTUPDATER, "No data to publish");
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
        logDebug1(WM_CONTENTUPDATER, "PubSubPublisher - Starting process");

        publish(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _PUB_SUB_PUBLISHER_HPP
