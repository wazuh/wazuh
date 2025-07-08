/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * July 7, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCK_HTTP_REQUEST_HPP
#define _MOCK_HTTP_REQUEST_HPP

#include "IURLRequest.hpp"
#include <gmock/gmock.h>
#include <string>
#include <variant>
#include <vector>

// Type aliases to avoid GMock issues with comma in template parameters
using RequestParamsVariant = std::variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>>;

/**
 * @brief GMock-based mock for HTTPRequest class
 *
 * This mock replaces the custom MockHttpRequest class with a proper GMock implementation
 * that provides better test isolation and flexibility.
 */
class MockHTTPRequest : public IURLRequest
{
public:
    MOCK_METHOD(void,
                download,
                (RequestParamsVariant requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    MOCK_METHOD(void,
                post,
                (RequestParamsVariant requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    MOCK_METHOD(void,
                get,
                (RequestParamsVariant requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    MOCK_METHOD(void,
                put,
                (RequestParamsVariant requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    MOCK_METHOD(void,
                patch,
                (RequestParamsVariant requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    MOCK_METHOD(void,
                delete_,
                (RequestParamsVariant requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    // Static instance method required by IndexerConnectorSyncImpl
    static MockHTTPRequest& instance()
    {
        static MockHTTPRequest inst;
        return inst;
    }
};

#endif // _MOCK_HTTP_REQUEST_HPP
