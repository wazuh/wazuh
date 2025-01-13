/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _VULNERABILITY_SCANNER_FACADE_HPP
#define _VULNERABILITY_SCANNER_FACADE_HPP

#include "indexerConnector.hpp"
#include "routerSubscriber.hpp"
#include "singleton.hpp"
#include "timeHelper.h"
#include <functional>
#include <harvesterConfiguration.hpp>
#include <memory>
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
               const HarvesterConfiguration& configuration);

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
    // void pushEvent(const std::vector<char>& message, BufferType type) const
    // {
    //     flatbuffers::FlatBufferBuilder builder;
    //     auto object = CreateMessageBufferDirect(
    //         builder, reinterpret_cast<const std::vector<int8_t>*>(&message), type, Utils::getSecondsFromEpoch());

    //     builder.Finish(object);
    //     auto bufferData = reinterpret_cast<const char*>(builder.GetBufferPointer());
    //     size_t bufferSize = builder.GetSize();
    //     const rocksdb::Slice messageSlice(bufferData, bufferSize);
    //     m_eventDispatcher->push(messageSlice);
    // }

private:
    /**
     * @brief This class models the different actions that should be performed when configurations changes are detected.
     *
     */
    // void processEvent(ScanOrchestrator& scanOrchestrator, const MessageBuffer* message) const;
    std::unique_ptr<RouterSubscriber> m_syscollectorDeltasSubscription;
    std::unique_ptr<RouterSubscriber> m_syscollectorRsyncSubscription;
    std::unique_ptr<RouterSubscriber> m_wdbAgentEventsSubscription;
    std::shared_ptr<IndexerConnector> m_indexerConnector;
    bool m_noWaitToStop {true};
    std::shared_ptr<EventDispatcher> m_eventDispatcher;
};

#endif // _VULNERABILITY_SCANNER_FACADE_HPP
