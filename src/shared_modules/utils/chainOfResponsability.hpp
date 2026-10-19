/*
 * Wazuh Vulnerability scanner
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CHAIN_OF_RESPONSABILITY_HPP
#define _CHAIN_OF_RESPONSABILITY_HPP

#include <memory>

// LCOV_EXCL_START
template<typename T>
/**
 * @brief Template handle class for the steps on the chain
 *
 */
class Handler
{
public:
    virtual ~Handler() = default;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    virtual std::shared_ptr<Handler> setNext(std::shared_ptr<Handler> handler) = 0;

    /**
     * @brief Set the last handler on the chain
     *
     * @param handler handler that will be set as the last on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * last
     */
    virtual std::shared_ptr<Handler> setLast(std::shared_ptr<Handler> handler) = 0;

    /**
     * @brief Triggers handler action
     *
     * @param data template type used by the handler
     * @return T next handler on the chain
     */
    virtual T handleRequest(T data) = 0;
};
// LCOV_EXCL_STOP

template<typename T>
/**
 * @brief AbstractHandler class
 *
 */
class AbstractHandler : public Handler<T>
{
private:
    /**
     * @brief Next handler on the chain
     *
     */
    std::shared_ptr<Handler<T>> m_next;

public:
    AbstractHandler() = default;
    // LCOV_EXCL_START
    virtual ~AbstractHandler() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Set the next handler on the chain
     *
     * @param requestNext handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler<T>> the same handler that has been set as
     * next
     */
    // LCOV_EXCL_START
    std::shared_ptr<Handler<T>> setNext(const std::shared_ptr<Handler<T>> requestNext) override
    {
        m_next = requestNext;
        return requestNext;
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Set the last handler on the chain
     *
     * @param requestLast handler that will be set as the last on the chain
     * @return std::shared_ptr<Handler<T>> the same handler that has been set as
     * last
     */
    // LCOV_EXCL_START
    std::shared_ptr<Handler<T>> setLast(const std::shared_ptr<Handler<T>> requestLast) override
    {
        if (m_next)
        {
            return m_next->setLast(requestLast);
        }
        return this->setNext(requestLast);
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Triggers handler action
     *
     * @param data template type used by the handler
     * @return T next handler on the chain if exists, data otherwise
     */
    T handleRequest(T data) override
    {
        if (m_next)
        {
            return m_next->handleRequest(data);
        }
        return data;
    }

    /**
     * @brief Get next step on the chain
     *
     * @return std::shared_ptr<AbstractHandler> next handler on the chain
     */
    std::shared_ptr<AbstractHandler> next() const
    {
        return m_next;
    }
};

#endif // _CHAIN_OF_RESPONSABILITY_HPP
