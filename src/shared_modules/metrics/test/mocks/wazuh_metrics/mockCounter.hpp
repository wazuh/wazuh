/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_METRICS_MOCKS_MOCK_COUNTER_HPP
#define _WAZUH_METRICS_MOCKS_MOCK_COUNTER_HPP

#include <gmock/gmock.h>

#include <wazuh_metrics/iMetric.hpp>

namespace wazuh::metrics::mocks
{

    /**
     * @brief Mock implementation of ICounter for testing
     */
    class MockCounter : public ICounter
    {
    public:
        MOCK_METHOD(const std::string&, name, (), (const, override));
        MOCK_METHOD(MetricType, type, (), (const, override));
        MOCK_METHOD(bool, isEnabled, (), (const, override));
        MOCK_METHOD(void, enable, (), (override));
        MOCK_METHOD(void, disable, (), (override));
        MOCK_METHOD(void, reset, (), (override));
        MOCK_METHOD(double, value, (), (const, override));
        MOCK_METHOD(void, add, (uint64_t), (override));
        MOCK_METHOD(uint64_t, get, (), (const, override));
    };

} // namespace wazuh::metrics::mocks

#endif // _WAZUH_METRICS_MOCKS_MOCK_COUNTER_HPP
