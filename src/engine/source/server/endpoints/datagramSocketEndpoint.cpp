/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstring>
#include <fcntl.h>
#include <glog/logging.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "datagramSocketEndpoint.hpp"
#include "protocolHandler.hpp"

using std::endl;
using std::string;

using uvw::ErrorEvent;
using uvw::Loop;
using uvw::UDPDataEvent;
using uvw::UDPHandle;

static constexpr int MAX_MSG_SIZE = 65536 + 512;

namespace engineserver::endpoints
{

/**
 * @brief This function opens, binds and configures a unix datagram socket.
 * @todo The code was extracted from the Wazuh source, so it must be adapted
 * when the engine is integrated to the rest of the Wazuh code to avoid
 * code duplicity.
 * @param path (const char *) Contains the absolute path to the unix datagram socket
 * @return (int) Returns either the file descriptor value or -1
 */
static inline int OS_BindUnixDomain(const char * path)
{
    struct sockaddr_un n_us;
    int socketFd = 0;

    /*
       From the man pages:
        unlink() deletes a name from the filesystem.  If that name was the last
       link to a file and no processes have the file open, the file is deleted
       and the space it was  using  is  made available for reuse.
    */
    unlink(path);

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path, sizeof(n_us.sun_path) - 1);

    if ((socketFd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0)
    {
        return -1;
    }

    if (bind(socketFd, (struct sockaddr *) &n_us, SUN_LEN(&n_us)) < 0)
    {
        close(socketFd);
        return -1;
    }

    /* Change permissions */
    if (chmod(path, 0660) < 0)
    {
        close(socketFd);
        return -1;
    }

    int len;
    socklen_t optlen = sizeof(len);

    /* Get current maximum size */
    if (getsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, (void *) &len, &optlen) == -1)
    {
        len = 0;
    }

    /* Set maximum message size */
    if (len < MAX_MSG_SIZE)
    {
        len = MAX_MSG_SIZE;
        if (setsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, (const void *) &len, optlen) < 0)
        {
            close(socketFd);
            return -1;
        }
    }

    // Set close-on-exec
    if (fcntl(socketFd, F_SETFD, FD_CLOEXEC) == -1)
    {
        LOG(ERROR) << "Cannot set close-on-exec flag to socket: %s (%d)" << strerror(errno) << errno << endl;
    }

    return (socketFd);
}

DatagramSocketEndpoint::DatagramSocketEndpoint(const string & path, ServerOutput & eventBuffer)
    : BaseEndpoint{path, eventBuffer}, m_loop{Loop::getDefault()}, m_handle{m_loop->resource<DatagramSocketHandle>()}
{
    auto protocolHandler = std::make_shared<ProtocolHandler>();

    m_handle->on<ErrorEvent>(
        [](const ErrorEvent & event, DatagramSocketHandle & datagramSocketHandle)
        {
            LOG(ERROR) << "Datagram Socket Server (" << datagramSocketHandle.sock().ip.c_str() << ":"
                       << datagramSocketHandle.sock().port << ") error: code=" << event.code()
                       << "; name=" << event.name() << "; message=" << event.what() << endl;
        });

    m_handle->on<DatagramSocketEvent>(
        [this, protocolHandler](const DatagramSocketEvent & event, DatagramSocketHandle & handle)
        {
            auto client = handle.loop().resource<DatagramSocketHandle>();

            client->on<ErrorEvent>(
                [](const ErrorEvent & event, DatagramSocketHandle & client)
                {
                    LOG(ERROR) << "Datagram Socket Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                               << ") error: code=" << event.code() << "; name=" << event.name()
                               << "; message=" << event.what() << endl;
                });

            try
            {
                const auto result = protocolHandler->process(event.data.get(), event.length);

                if (result)
                {
                    const auto events = result.value().data();

                    while (!this->m_out.try_enqueue_bulk(events, result.value().size()))
                        ;
                }
                else
                {
                    LOG(ERROR) << "Datagram Socket DataEvent: Error processing data" << endl;
                }
            }
            catch (const std::exception & e)
            {
                LOG(ERROR) << e.what() << '\n';
            }
        });

    m_socketFd = OS_BindUnixDomain(m_path.c_str());

    if (m_socketFd <= 0)
    {
        LOG(ERROR) << "Error while opening socket: %s (%d)." << strerror(errno) << errno << endl;
    }
}

void DatagramSocketEndpoint::run(void)
{
    if (m_socketFd > 0)
    {
        m_handle->open(m_socketFd);
        m_handle->recv();
        m_loop->run<Loop::Mode::DEFAULT>();
    }
    else
    {
        LOG(ERROR) << "Socket's file descriptor is invalid: FD=" << m_socketFd << "." << endl;
    }
}

void DatagramSocketEndpoint::close(void)
{
    m_loop->stop();                                                 /// Stops the loop
    m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    m_loop->clear();
    m_loop->close();
}

DatagramSocketEndpoint::~DatagramSocketEndpoint()
{
    close();
}

} // namespace engineserver::endpoints
