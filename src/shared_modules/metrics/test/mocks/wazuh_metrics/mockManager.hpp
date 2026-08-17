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

#ifndef _WAZUH_METRICS_MOCKS_MOCK_MANAGER_HPP
#define _WAZUH_METRICS_MOCKS_MOCK_MANAGER_HPP

#include <gmock/gmock.h>

#include <wazuh_metrics/iManager.hpp>

namespace wazuh::metrics::mocks
{

    /**
     * @brief Mock implementation of IManager for testing
     */
    class MockManager : public IManager
    {
    public:
        MOCK_METHOD(std::shared_ptr<ICounter>,
                    getOrCreateCounter,
                    (const std::string&, const std::string&, const std::string&),
                    (override));

        MOCK_METHOD(std::shared_ptr<IGaugeInt>,
                    getOrCreateGaugeInt,
                    (const std::string&, const std::string&, const std::string&),
                    (override));

        MOCK_METHOD(std::shared_ptr<IHistogram>,
                    getOrCreateHistogram,
                    (const std::string&, const std::string&, const std::string&),
                    (override));

        MOCK_METHOD(void,
                    registerPullMetric,
                    (const std::string&, std::function<uint64_t()>, const std::string&, const std::string&),
                    (override));

        MOCK_METHOD(void,
                    registerPullMetricDouble,
                    (const std::string&, std::function<double()>, const std::string&, const std::string&),
                    (override));

        MOCK_METHOD(std::shared_ptr<IMetric>, get, (const std::string&), (const, override));

        MOCK_METHOD(Metadata, getMetadata, (const std::string&), (const, override));

        MOCK_METHOD(bool, exists, (const std::string&), (const, override));

        MOCK_METHOD(std::vector<std::string>, getAllNames, (), (const, override));

        MOCK_METHOD(size_t, count, (), (const, override));

        MOCK_METHOD(void, enableAll, (), (override));

        MOCK_METHOD(void, disableAll, (), (override));

        MOCK_METHOD(bool, isEnabled, (), (const, override));

        MOCK_METHOD(void, clear, (), (override));
    };

} // namespace wazuh::metrics::mocks

#endif // _WAZUH_METRICS_MOCKS_MOCK_MANAGER_HPP
