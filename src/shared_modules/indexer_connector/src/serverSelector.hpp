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
#include <initializer_list>
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
                             const uint32_t timeout = DEFAULT_MONITORING_INTERVAL,
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
     * Prefers an Available host; a Throttled one (it answered 429, so it is alive but shedding load)
     * is used only when no host is Available, and the call throws only when every host is Down. With a
     * single host this is the same as accepting anything that is not Down.
     *
     * @return std::string Server address.
     */
    std::string_view getNext()
    {
        const std::string_view initialValue {RoundRobinSelector<std::string>::getNext()};

        for (const auto accepted : {HostState::Available, HostState::Throttled})
        {
            auto candidate {initialValue};
            do
            {
                if (m_monitoring->state(candidate) == accepted)
                {
                    return candidate;
                }
                candidate = RoundRobinSelector<std::string>::getNext();
            } while (candidate.compare(initialValue) != 0);
        }

        throw std::runtime_error("No available server. Unavailable nodes: " +
                                 m_monitoring->getUnavailableServersDetails());
    }

    /**
     * @brief Check have a server available.
     *
     * A pure inspection: it must not advance the round-robin cursor, or every health probe
     * (the /stats and /config handlers call this) would silently skip a healthy host for the
     * next real request and bias the traffic distribution.
     *
     * @return true if have a server available, false otherwise.
     */
    bool isAvailable() const
    {
        for (const auto& server : RoundRobinSelector<std::string>::values())
        {
            if (m_monitoring->isAvailable(server))
            {
                return true;
            }
        }
        return false;
    }
};

#endif // _SERVER_SELECTOR_HPP
