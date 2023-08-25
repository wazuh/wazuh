/*
 * Wazuh urlRequest test component
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCKREQUEST_HPP
#define _MOCKREQUEST_HPP

#include "urlRequest.hpp"

/**
 * @brief This class is a wrapper for the cURL library.
 */
template<typename T>
class MockRequest : public cURLRequest<MockRequest<T>, T>
{
public:
    /**
     * @brief Constructor.
     * @param requestImplementator The request implementator instance.
     */
    explicit MockRequest(std::shared_ptr<IRequestImplementator> requestImplementator)
        : cURLRequest<MockRequest<T>, T>(requestImplementator)
    {
    }
};

#endif // _MOCKREQUEST_HPP
