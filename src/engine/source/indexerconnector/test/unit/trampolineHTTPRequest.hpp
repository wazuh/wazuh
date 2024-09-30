/*
 * Wazuh Indexer Connector - Trampoline for HTTPRequest lib.
 * Copyright (C) 2015, Wazuh Inc.
 * August 30, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TRAMPOLINE_HTTP_REQUEST_HPP
#define _TRAMPOLINE_HTTP_REQUEST_HPP

#include "base/utils/singleton.hpp"
#include "httpRequest/mockHttpRequest.hpp"

extern std::shared_ptr<httprequest::mock::MockHTTPRequest> spHTTPRequest;

/**
 * @brief Trampoline class for HTTPRequest class.
 */
class TrampolineHTTPRequest final : public Singleton<TrampolineHTTPRequest>
{
public:
    TrampolineHTTPRequest() {};

    virtual ~TrampolineHTTPRequest()
    {
        // Reset trampoline
        spHTTPRequest.reset();
    };

    /**
     * @brief Performs a HTTP GET request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    void get(RequestParameters requestParameters,
             PostRequestParameters postRequestParameters = {},
             ConfigurationParameters configurationParameters = {})
    {
        spHTTPRequest->get(requestParameters, postRequestParameters, configurationParameters);
    }
};

#endif // _TRAMPOLINE_HTTP_REQUEST_HPP
