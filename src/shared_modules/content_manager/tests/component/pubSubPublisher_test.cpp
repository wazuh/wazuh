/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "pubSubPublisher_test.hpp"
#include "routerProvider.hpp"
#include "gtest/gtest.h"
#include <memory>
#include <stdexcept>
#include <string>

/*
 * @brief Tests the instantiation of the PubSubPublisher class
 */
TEST_F(PubSubPublisherTest, instantiation)
{
    // Check that the PubSubPublisher class can be instantiated
    EXPECT_NO_THROW(std::make_shared<PubSubPublisher>());
}

/*
 * @brief Tests publish empty data.
 */
TEST_F(PubSubPublisherTest, TestPublishEmptyData)
{
    m_spUpdaterBaseContext->spChannel = std::make_shared<RouterProvider>("component-tests");
    m_spUpdaterBaseContext->spChannel->start();

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    EXPECT_NO_THROW(m_spPubSubPublisher->handleRequest(m_spUpdaterContext));

    m_spUpdaterBaseContext->spChannel->stop();

    EXPECT_FALSE(m_spUpdaterContext->data.empty());
}

/*
 * @brief Tests publish valid data.
 */
TEST_F(PubSubPublisherTest, TestPublishValidData)
{
    m_spUpdaterBaseContext->spChannel = std::make_shared<RouterProvider>("component-tests");
    m_spUpdaterBaseContext->spChannel->start();

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;
    m_spUpdaterContext->data.at("paths").push_back("/dummy/path");

    EXPECT_NO_THROW(m_spPubSubPublisher->handleRequest(m_spUpdaterContext));

    m_spUpdaterBaseContext->spChannel->stop();

    EXPECT_FALSE(m_spUpdaterContext->data.empty());
}

/*
 * @brief Tests publish valid data without start the RouterProvider.
 */
TEST_F(PubSubPublisherTest, TestPublishValidDataWithouStartTheRouterProvider)
{
    m_spUpdaterBaseContext->spChannel = std::make_shared<RouterProvider>("component-tests");

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;
    m_spUpdaterContext->data = R"({ "type": "raw", "paths": ["/dummy/path"], "stageStatus": [] })"_json;

    EXPECT_THROW(m_spPubSubPublisher->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_THROW(m_spUpdaterBaseContext->spChannel->stop(), std::runtime_error);

    EXPECT_FALSE(m_spUpdaterContext->data.empty());
}

/*
 * @brief Tests publish empty data without start the RouterProvider.
 */
TEST_F(PubSubPublisherTest, TestPublishEmptyDataWithouStartTheRouterProvider)
{
    m_spUpdaterBaseContext->spChannel = std::make_shared<RouterProvider>("component-tests");

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;
    m_spUpdaterContext->data.clear();

    EXPECT_NO_THROW(m_spPubSubPublisher->handleRequest(m_spUpdaterContext));

    EXPECT_THROW(m_spUpdaterBaseContext->spChannel->stop(), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.empty());
}
