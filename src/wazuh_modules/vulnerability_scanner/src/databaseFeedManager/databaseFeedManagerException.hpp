/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * June 04, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DATABASE_FEED_MANAGER_EXCEPTION_HPP
#define _DATABASE_FEED_MANAGER_EXCEPTION_HPP

#include <stdexcept>

/**
 * @brief Custom exception for the @see DatabaseFeedManager class.
 *
 */
class DatabaseFeedManagerException : public std::exception
{
public:
    /**
     * @brief Overload what() method.
     *
     * @return const char* The message to be shown.
     */
    // LCOV_EXCL_START
    const char* what() const noexcept override
    {
        return m_msg.what();
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Construct a new exception object
     *
     * @param message The message to be shown.
     */
    explicit DatabaseFeedManagerException(const std::string& message)
        : m_msg {message} // NOLINT
    {
    }

private:
    std::runtime_error m_msg;
};

#endif // _DATABASE_FEED_MANAGER_EXCEPTION_HPP
