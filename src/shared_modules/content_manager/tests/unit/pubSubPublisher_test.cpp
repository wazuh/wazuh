/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "pubSubPublisher_test.hpp"
#include "pubSubPublisher.hpp"
#include "updaterContext.hpp"
#include <gmock/gmock.h>
#include <memory>
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
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    EXPECT_NO_THROW(m_spPubSubPublisher->handleRequest(m_spUpdaterContext));

    EXPECT_FALSE(m_spUpdaterContext->data.empty());
}

/*
 * @brief Tests publish valid data.
 */
TEST_F(PubSubPublisherTest, TestPublishValidData)
{
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;
    m_spUpdaterContext->data.at("paths").push_back("/dummy/path");

    EXPECT_NO_THROW(m_spPubSubPublisher->handleRequest(m_spUpdaterContext));

    EXPECT_FALSE(m_spUpdaterContext->data.empty());
}
