/*
 * Wazuh Utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2012.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CHAIN_OF_RESPONSABILITY_HPP
#define _CHAIN_OF_RESPONSABILITY_HPP

#include <memory>

template <typename T>
class Handler
{
    public:
        virtual ~Handler() = default;
        virtual std::shared_ptr<Handler> setNext(const std::shared_ptr<Handler> handler) = 0;
        virtual T handleRequest(T data) = 0;
};

template <typename T>
class AbstractHandler : public Handler<T>
{
    private:
        std::shared_ptr<Handler<T>> m_next;
    public:
        AbstractHandler() = default;
        virtual ~AbstractHandler() = default;

        virtual std::shared_ptr<Handler<T>> setNext(const std::shared_ptr<Handler<T>> requestNext) override
        {
            m_next = requestNext;
            return requestNext;
        }

        virtual T handleRequest(T data) override
        {
            if (m_next)
            {
                return m_next->handleRequest(data);
            }
            return data;
        }

        std::shared_ptr<AbstractHandler> next() const
        {
            return m_next;
        }

};

#endif // _CHAIN_OF_RESPONSABILITY_HPP

