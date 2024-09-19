/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 18, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PUB_SUB_PUBLISHER_EXCEPTIONS_HPP
#define _PUB_SUB_PUBLISHER_EXCEPTIONS_HPP

#include <exception>
#include <string>

/**
 * @brief Identifies an exception when processing offsets.
 *
 */
class OffsetProcessingException final : public std::exception
{
    const std::string m_errorMessage; ///< Exception message.

public:
    /**
     * @brief Class constructor.
     *
     * @param errorMessage Exception message.
     */
    explicit OffsetProcessingException(std::string errorMessage)
        : m_errorMessage(std::move(errorMessage))
    {
    }

    /**
     * @brief Returns the exception message.
     *
     * @return const char* Message.
     */
    const char* what() const noexcept override
    {
        return m_errorMessage.c_str();
    }
};

/**
 * @brief Identifies an exception when processing a snapshot.
 *
 */
class SnapshotProcessingException final : public std::exception
{
    const std::string m_errorMessage; ///< Exception message.

public:
    /**
     * @brief Class constructor.
     *
     * @param errorMessage Exception message.
     */
    explicit SnapshotProcessingException(std::string errorMessage)
        : m_errorMessage(std::move(errorMessage))
    {
    }

    /**
     * @brief Returns the exception message.
     *
     * @return const char* Message.
     */
    const char* what() const noexcept override
    {
        return m_errorMessage.c_str();
    }
};

#endif // _PUB_SUB_PUBLISHER_EXCEPTIONS_HPP
