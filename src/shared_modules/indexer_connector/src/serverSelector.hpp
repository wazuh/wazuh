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
class ServerSelector final : private RoundRobinSelector<std::string>
{
private:
    std::shared_ptr<Monitoring> m_monitoring;

public:
    ~ServerSelector() = default;

    /**
     * @brief Class constructor. Initializes Round Robin selector and monitoring.
     *
     * @param values Servers to be selected.
     * @param timeout Timeout for monitoring.
     * @param authentication Object that provides secure communication.
     */
    explicit ServerSelector(const std::vector<std::string>& values,
                            const uint32_t timeout = INTERVAL,
                            const SecureCommunication& authentication = {})
        : RoundRobinSelector<std::string>(values)
    {
        m_monitoring = std::make_shared<Monitoring>(values, timeout, authentication);
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
};

#endif // _SERVER_SELECTOR_HPP
