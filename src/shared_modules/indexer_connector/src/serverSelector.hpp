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
                throw std::runtime_error("No available server");
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
