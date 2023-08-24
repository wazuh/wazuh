/*
 * Wazuh http request
 * Copyright (C) 2015, Wazuh Inc.
 * July 10, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCKREQUESTIMPLEMENTATOR_HPP
#define _MOCKREQUESTIMPLEMENTATOR_HPP

#include "IRequestImplementator.hpp"
#include "gmock/gmock.h"
/**
 * @brief This class is a wrapper to perform requests.
 */
class RequestWrapper final : public IRequestImplementator
{
public:
    RequestWrapper() = default;
    virtual ~RequestWrapper() = default;

    /**
     * @brief Mock method to set request options.
     */
    MOCK_METHOD(void, setOption, (const OPTION_REQUEST_TYPE optIndex, void* ptr), (override));
    /**
     * @brief Mock method to set request options.
     */
    MOCK_METHOD(void, setOption, (const OPTION_REQUEST_TYPE optIndex, const std::string& opt), (override));
    /**
     * @brief Mock method to set request options.
     */
    MOCK_METHOD(void, setOption, (const OPTION_REQUEST_TYPE optIndex, const long int opt), (override));
    /**
     * @brief Mock method to set execute the request.
     */
    MOCK_METHOD(void, execute, (), (override));
    /**
     * @brief Mock method to get the response.
     */
    MOCK_METHOD(const std::string, response, (), (override));
    /**
     * @brief Mock method to append a header.
     */
    MOCK_METHOD(void, appendHeader, (const std::string& header), (override));
};

#endif // _MOCKREQUESTIMPLEMENTATOR_HPP

