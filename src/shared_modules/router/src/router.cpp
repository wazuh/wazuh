/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "router.h"
#include "routerFacade.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"

void RouterModule::initialize(const std::function<void(const modules_log_level_t, const std::string&)>& /*logFunction*/)
{
    // Init logger.
    // Init socket to receive messages from remoted and send them to the right module subscribed.
    // Init socket to receive remote subscribers.
    RouterFacade::instance().initialize();
}

void RouterModule::destroy()
{
    // clean subscribers.
    // Destroy socket.
    RouterFacade::instance().destroy();
}

void RouterProvider::send(const std::vector<char>& data)
{
    // Send data to the right provider.
    RouterFacade::instance().push(m_topicName, data);
}

void RouterProvider::start()
{
    // Add provider to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().initProviderLocal(m_topicName);
    }
    else
    {
        RouterFacade::instance().initProviderRemote(m_topicName);
    }
}

void RouterProvider::stop()
{
    // Add subscriber to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().removeProviderLocal(m_topicName);
    }
    else
    {
        RouterFacade::instance().removeProviderRemote(m_topicName);
    }
}

void RouterSubscriber::subscribe(const std::function<void(const std::vector<char>&)>& callback)
{
    // Add subscriber to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().addSubscriber(m_topicName, m_subscriberId, callback);
    }
    else
    {
        RouterFacade::instance().addSubscriberRemote(m_topicName, m_subscriberId, callback);
    }
}

void RouterSubscriber::unsubscribe()
{
    // Remove subscriber to the list.
    if (m_isLocal)
    {
        RouterFacade::instance().removeSubscriberLocal(m_topicName, m_subscriberId);
    }
    else
    {
        RouterFacade::instance().removeSubscriberRemote(m_topicName, m_subscriberId);
    }
}

#ifdef __cplusplus
extern "C"
{
#endif

    void router_start(log_callback_t callbackLog)
    {
        std::ignore = callbackLog;
        RouterFacade::instance().initialize();
    }

    void router_stop()
    {
        RouterFacade::instance().destroy();
    }

#ifdef __cplusplus
}
#endif

