/*
 * Wazuh databaseFeedManager
 * Copyright (C) 2015, Wazuh Inc.
 * January 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _CHAINOFRESPONSABILITYMOCK_HPP
#define _CHAINOFRESPONSABILITYMOCK_HPP

#include "gmock/gmock.h"
#include <memory>

/**
 * @class MockAbstractHandler
 *
 * @brief Mock class for simulating an AbstractHandler object.
 */
template<typename T>
class MockAbstractHandler
{
public:
    MockAbstractHandler() = default;
    virtual ~MockAbstractHandler() = default;

    /**
     * @brief Mock method for setNext.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(std::shared_ptr<MockAbstractHandler<T>>, setNext, (const std::shared_ptr<MockAbstractHandler<T>> requestNext), ());

    /**
     * @brief Mock method for setNext.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(std::shared_ptr<MockAbstractHandler<T>>, setLast, (const std::shared_ptr<MockAbstractHandler<T>> requestLast), ());

    /**
     * @brief Mock method for handleRequest.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(T, handleRequest, (T data), ());

    /**
     * @brief Mock method for handleRequest.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(std::shared_ptr<MockAbstractHandler<T>>, next, (), (const));
};

#endif // _CHAINOFRESPONSABILITYMOCK_HPP
