/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EVENT_ENDPOINT_H
#define _EVENT_ENDPOINT_H

#include <uvw/udp.hpp>

#include "baseEndpoint.hpp"

namespace engineserver::endpoints
{

/**
 * @brief Implements Unix Datagram Socket endpoint by using uvw library.
 *
 */
class EventEndpoint : public BaseEndpoint
{
protected:
    using DatagramSocketEvent = uvw::UDPDataEvent;
    using DatagramSocketHandle = uvw::UDPHandle;
    using concurrentQueue = moodycamel::BlockingConcurrentQueue<std::string>;

private:
    int m_socketFd;

    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<DatagramSocketHandle> m_handle;
    std::shared_ptr<concurrentQueue> m_eventQueue;

public:
    /**
     * @brief Construct a new EventEndpoint object.
     *
     * @param path (std::string) Absolute path to the datagram socket.
     * @param eventBuffer (ServerOutput) Reference to the event queue.
     */
    explicit EventEndpoint(const std::string& path,
                           std::shared_ptr<concurrentQueue> eventQueue);

    ~EventEndpoint();

    void run(void);

    void configure() override;

    void close(void);

    std::shared_ptr<concurrentQueue> getEventQueue() const;
};

} // namespace engineserver::endpoints

#endif // _EVENT_ENDPOINT_H
