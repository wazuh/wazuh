/*
 * Wazuh Utils - Singleton template
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 03, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _EPOLL_WRAPPER_HPP
#define _EPOLL_WRAPPER_HPP

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <sys/epoll.h>
#include <unistd.h>

class EpollWrapper final
{
private:
    int m_epollFD;

public:
    // Constructor
    EpollWrapper()
    {
        m_epollFD = epoll_create1(0);
        if (m_epollFD == -1)
        {
            throw std::runtime_error("Error creating epoll instance");
        }
    }

    // Destructor
    ~EpollWrapper()
    {
        ::close(m_epollFD);
    }

    // Disable copy constructor
    EpollWrapper(const EpollWrapper&) = delete;

    // Disable copy assignment operator
    EpollWrapper& operator=(const EpollWrapper&) = delete;

    // Disable move constructor
    EpollWrapper(EpollWrapper&&) = delete;

    // Disable move assignment operator
    EpollWrapper& operator=(EpollWrapper&&) = delete;

    // Wait for events on an epoll instance (epollFD)
    int wait(epoll_event* events, int maxevents, int timeout) const
    {
        return epoll_wait(m_epollFD, events, maxevents, timeout);
    }

    // Add a file descriptor (fd) to an epoll instance (epollFD)
    void addDescriptor(const int fd, const uint32_t events) const
    {
        epoll_event event {};
        event.events = events;
        event.data.fd = fd;

        if (epoll_ctl(m_epollFD, EPOLL_CTL_ADD, fd, &event) == -1)
        {
            std::cerr << "Error adding FD to interface." << std::endl;
        }
    }

    // Modify the events associated with a file descriptor (fd) in an epoll instance (epollFD)
    void modifyDescriptor(const int fd, const uint32_t events) const
    {
        epoll_event event {};
        event.events = events;
        event.data.fd = fd;

        if (epoll_ctl(m_epollFD, EPOLL_CTL_MOD, fd, &event) == -1)
        {
            std::cerr << "Error modifying FD from interface." << std::endl;
        }
    }

    // Delete a file descriptor (fd) from an epoll instance (epollFD)
    void deleteDescriptor(const int fd) const
    {
        if (epoll_ctl(m_epollFD, EPOLL_CTL_DEL, fd, nullptr) == -1)
        {
            std::cerr << "Error removing FD from interface." << std::endl;
        }
    }
};

#endif // _EPOLL_WRAPPER_HPP
