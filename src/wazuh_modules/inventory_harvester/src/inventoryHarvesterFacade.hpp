/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_ORCHESTRATOR_FACADE_HPP
#define _INVENTORY_ORCHESTRATOR_FACADE_HPP

#include "flatbuffers/include/messageBuffer_generated.h"
#include "routerSubscriber.hpp"
#include "singleton.hpp"
#include "threadEventDispatcher.hpp"
#include "timeHelper.h"
#include <functional>
#include <json.hpp>
#include <memory>
#include <queue>           // Add this line to include the <queue> header file
#include <rocksdb/slice.h> // Add this line to include the rocksdb namespace
#include <string>

using EventDispatcher = TThreadEventDispatcher<rocksdb::Slice,
                                               rocksdb::PinnableSlice,
                                               std::function<void(std::queue<rocksdb::PinnableSlice>&)>>;

/**
 * @brief InventoryHarvesterFacade class.
 *
 */
class InventoryHarvesterFacade final : public Singleton<InventoryHarvesterFacade>
{
public:
    /**
     * @brief Starts facade.
     *
     * @param logFunction Log function.
     * @param configuration Facade configuration.
     */
    void start(const std::function<void(const int,
                                        const std::string&,
                                        const std::string&,
                                        const int,
                                        const std::string&,
                                        const std::string&,
                                        va_list)>& logFunction,
               const nlohmann::json& configuration);

    /**
     * @brief Stops facade.
     *
     */
    void stop();

    /**
     * @brief push event to the event dispatcher.
     * This method is used to push an event to the event dispatcher.
     * @param message event message.
     * @param type event type.
     */
    void pushFimEvent(const std::vector<char>& message, BufferType type) const
    {
        flatbuffers::FlatBufferBuilder builder;
        auto object = CreateMessageBufferDirect(
            builder, reinterpret_cast<const std::vector<int8_t>*>(&message), type, Utils::getSecondsFromEpoch());

        builder.Finish(object);
        auto bufferData = reinterpret_cast<const char*>(builder.GetBufferPointer());
        size_t bufferSize = builder.GetSize();
        const rocksdb::Slice messageSlice(bufferData, bufferSize);
        m_eventFimInventoryDispatcher->push(messageSlice);
    }

    /**
     * @brief push event to the event dispatcher.
     * This method is used to push an event to the event dispatcher.
     * @param message event message.
     * @param type event type.
     */
    void pushSystemEvent(const std::vector<char>& message, BufferType type) const
    {
        flatbuffers::FlatBufferBuilder builder;
        auto object = CreateMessageBufferDirect(
            builder, reinterpret_cast<const std::vector<int8_t>*>(&message), type, Utils::getSecondsFromEpoch());

        builder.Finish(object);
        auto bufferData = reinterpret_cast<const char*>(builder.GetBufferPointer());
        size_t bufferSize = builder.GetSize();
        const rocksdb::Slice messageSlice(bufferData, bufferSize);
        m_eventSystemInventoryDispatcher->push(messageSlice);
    }

private:
    /**
     * @brief This class models the different actions that should be performed when configurations changes are detected.
     *
     */
    // void processEvent(ScanOrchestrator& scanOrchestrator, const MessageBuffer* message) const;
    std::unique_ptr<RouterSubscriber> m_inventoryDeltasSubscription;
    std::unique_ptr<RouterSubscriber> m_harvesterRsyncSubscription;
    std::unique_ptr<RouterSubscriber> m_fimDeltasSubscription;
    std::unique_ptr<RouterSubscriber> m_wdbAgentEventsSubscription;
    bool m_noWaitToStop {true};
    std::shared_ptr<EventDispatcher> m_eventSystemInventoryDispatcher;
    std::shared_ptr<EventDispatcher> m_eventFimInventoryDispatcher;

    void initInventoryDeltasSubscription();
    void initInventoryRsyncSubscription();
    void initFimDeltasSubscription();
    void initFimRsyncSubscription();
    void initWazuhDBEventSubscription();
    void initSystemEventDispatcher();
    void initFimEventDispatcher();
};

#endif // _INVENTORY_ORCHESTRATOR_FACADE_HPP
