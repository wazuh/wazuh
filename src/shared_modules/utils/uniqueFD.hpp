/*
 * Wazuh Utils
 * Copyright (C) 2015, Wazuh Inc.
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

namespace Utils
{

    /*
    * This class is intended to handle a file descriptor similar to a unique pointer in C++.
    */
    class UniqueFD
    {
        public:
            explicit UniqueFD(const int fd) : m_fd(fd) { }
            ~UniqueFD()
            {
                clear();
            }

            UniqueFD(const UniqueFD&) = delete;
            UniqueFD& operator=(const UniqueFD&) = delete;
            UniqueFD(UniqueFD&& other) : m_fd(other.m_fd)
            {
                other.m_fd = -1;
            }

            /**
             * @brief Assign a new file descriptor and close the file descriptor you have assigned.
             *
             * @param other New file descriptor associated.
             *
             * @return Returns the reference to the object with new file descriptor.
             */
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

            /**
             * @brief Gets file descriptor associated of the object.
             *
             * @return Returns the associated file descriptor.
             */
            int get() const
            {
                return m_fd;
            }

            /**
             * @brief Clean the file descriptor associated to the class. First, close
             *  the associated file descriptor if it has one.
             *
             * @param fd File descriptor that is associated with class
             */
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
