/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * April 22, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WDB_SOCKET_DB_WRAPPER_EXCEPTION_HPP
#define _WDB_SOCKET_DB_WRAPPER_EXCEPTION_HPP

#include <stdexcept>

/**
 * @brief SocketDbWrapperException class.
 *
 */
class SocketDbWrapperException : public std::exception
{
public:
    /**
     * @brief Overload what() method.
     *
     * @return const char*
     */
    // LCOV_EXCL_START
    const char* what() const noexcept override
    {
        return m_msg.what();
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Construct a new socket DB Wrapper Exception object
     *
     * @param message
     * @param agentId
     */
    explicit SocketDbWrapperException(const std::string& message)
        : m_msg {message} // NOLINT
    {
    }

private:
    std::runtime_error m_msg;
    std::string m_agentId;
};

#endif // _WDB_SOCKET_DB_WRAPPER_EXCEPTION_HPP
