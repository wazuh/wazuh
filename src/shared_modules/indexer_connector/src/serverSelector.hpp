/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * June 21, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SERVER_SELECTOR_HPP
#define _SERVER_SELECTOR_HPP

#include "monitoring.hpp"
#include "roundRobinSelector.hpp"
#include "secureCommunication.hpp"
#include <memory>
#include <string>

/**
 * @brief ServerSelector class.
 *
 */
template<typename HttpType>
class TServerSelector final : private RoundRobinSelector<std::string>
{
private:
    std::shared_ptr<TMonitoring<HttpType>> m_monitoring;

public:
    ~TServerSelector() = default;

    /**
     * @brief Class constructor. Initializes Round Robin selector and monitoring.
     *
     * @param values Servers to be selected.
     * @param timeout Timeout for monitoring.
     * @param authentication Object that provides secure communication.
     */
    explicit TServerSelector(const std::vector<std::string>& values,
                             const uint32_t timeout = INTERVAL,
                             const SecureCommunication& authentication = {},
                             HttpType* httpRequest = nullptr)
        : RoundRobinSelector<std::string>(values)
        , m_monitoring(std::make_shared<TMonitoring<HttpType>>(
              values, timeout, authentication, httpRequest ? httpRequest : &HttpType::instance()))
    {
    }

    /**
     * @brief Class constructor that ADOPTS an already-built monitor instead of creating its own.
     *
     * Lets several selectors -- and therefore several connectors in one process -- share a single
     * health-check thread and a single round of startup health checks, instead of one each. The
     * round-robin cursor stays private to each selector, which is deliberate: sharing the cursor
     * would widen the wrap-around detection in getNext() below, which is value-based and so can miss
     * its own starting index when several threads advance the same cursor.
     *
     * @param monitoring Monitor to share. Must be non-null.
     * @param values Servers to select from. MUST be the same list the monitor was built with:
     *               TMonitoring::isAvailable() throws std::out_of_range for a server it does not
     *               monitor, and its server map is fixed at construction.
     */
    explicit TServerSelector(std::shared_ptr<TMonitoring<HttpType>> monitoring, const std::vector<std::string>& values)
        : RoundRobinSelector<std::string>(values)
        , m_monitoring(std::move(monitoring))
    {
        if (!m_monitoring)
        {
            throw std::runtime_error("A server selector cannot be built on a null monitor");
        }
    }

    /**
     * @brief Get next selected server.
     *
     * @return std::string Server address.
     */
    std::string_view getNext()
    {
        std::string_view initialValue {RoundRobinSelector<std::string>::getNext()};
        auto retValue {initialValue};

        while (!m_monitoring->isAvailable(retValue))
        {
            retValue = RoundRobinSelector<std::string>::getNext();
            if (retValue.compare(initialValue) == 0)
            {
                throw std::runtime_error("No available server. Unavailable nodes: " +
                                         m_monitoring->getUnavailableServersDetails());
            }
        }
        return retValue;
    }

    /**
     * @brief Check have a server available.
     *
     * @return true if have a server available, false otherwise.
     */
    bool isAvailable()
    {
        std::string_view initialValue {RoundRobinSelector<std::string>::getNext()};
        auto server {initialValue};

        while (!m_monitoring->isAvailable(server))
        {
            server = RoundRobinSelector<std::string>::getNext();
            if (server.compare(initialValue) == 0)
            {
                return false;
            }
        }

        return true;
    }
};

#endif // _SERVER_SELECTOR_HPP
