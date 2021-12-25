/*
 * Wazuh Utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 25, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef UNIQUE_FD_H
#define UNIQUE_FD_H

#include <unistd.h>

namespace Utils {
    class UniqueFD {
    public:
        explicit UniqueFD(const int fd) : m_fd(fd) { }
        ~UniqueFD()
        {
            clear();
        }

        UniqueFD(const UniqueFD&) = delete;
        UniqueFD& operator=(const UniqueFD&) = delete;
        UniqueFD(UniqueFD&& other) : m_fd(other.m_fd) { other.m_fd = -1; }
        UniqueFD& operator=(UniqueFD&& other)
        {
            reset(other.release());
            return *this;
        }

        int release()
        {
            int fd = m_fd;
            m_fd = -1;
            return fd;
        }

        int get() const { return m_fd; }

        void reset(const int fd)
        {
            if (-1 != m_fd)
            {
                close(m_fd);
            }
            m_fd = fd;
        }

        void clear()
        {
            reset(-1);
        }
    private:
        int m_fd;
    };
}

#endif /* UNIQUE_FD_H */
