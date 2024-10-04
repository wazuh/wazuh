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

#include "base/utils/roundRobinSelector.hpp"
#include "monitoring.hpp"
#include <memory>
#include <string>

/**
 * @brief ServerSelector class.
 *
 */
template<typename TMonitoring>
class TServerSelector final : private RoundRobinSelector<std::string>
{
private:
    std::shared_ptr<TMonitoring> monitoring;

public:
    ~TServerSelector() = default;

    /**
     * @brief Class constructor. Initializes Round Robin selector and monitoring.
     *
     * @param values Servers to be selected.
     * @param timeout Timeout for monitoring.
     * @param secureCommunication Object that provides secure communication.
     */
    explicit TServerSelector(const std::vector<std::string>& values,
                             const uint32_t timeout = HEALTH_CHECK_TIMEOUT_MS,
                             const SecureCommunication& secureCommunication = {})
        : RoundRobinSelector<std::string>(values)
        , monitoring(std::make_shared<TMonitoring>(values, timeout, secureCommunication))
    {
    }

    /**
     * @brief Get next selected server.
     *
     * @return std::string Server address.
     */
    std::string getNext()
    {
        auto initialValue {RoundRobinSelector<std::string>::getNext()};
        auto retValue {initialValue};

        while (!monitoring->isAvailable(retValue))
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
