/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentRegister_test.hpp"
#include "contentManager.hpp"
#include "contentRegister.hpp"

/*
 * @brief Tests instantiation of the ContentRegister class
 */
TEST_F(ContentRegisterTest, TestInstantiation)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};

    auto& contentModule = ContentModule::instance();

    EXPECT_EQ(&contentModule, &ContentModule::instance());

    EXPECT_NO_THROW(contentModule.start(nullptr));

    EXPECT_NO_THROW(std::make_shared<ContentRegister>(topicName, m_parameters));

    EXPECT_NO_THROW(contentModule.stop());
}

/*
 * @brief Tests instantiation of the ContentRegister class with ondemand enabled
 */
TEST_F(ContentRegisterTest, TestInstantiationWithOnDemandEnabled)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};

    m_parameters["ondemand"] = true;

    auto& contentModule = ContentModule::instance();

    EXPECT_EQ(&contentModule, &ContentModule::instance());

    EXPECT_NO_THROW(contentModule.start(nullptr));

    EXPECT_NO_THROW(std::make_shared<ContentRegister>(topicName, m_parameters));

    EXPECT_NO_THROW(contentModule.stop());
}

/*
 * @brief Tests instantiation of the ContentRegister class and change scheduler interval
 */
TEST_F(ContentRegisterTest, TestInstantiationAndChangeSchedulerInterval)
{
    const auto& topicName {m_parameters.at("topicName").get_ref<const std::string&>()};
    const auto& interval {m_parameters.at("interval").get_ref<const size_t&>()};

    auto& contentModule = ContentModule::instance();

    EXPECT_EQ(&contentModule, &ContentModule::instance());

    EXPECT_NO_THROW(contentModule.start(nullptr));

    auto contentRegister {std::make_shared<ContentRegister>(topicName, m_parameters)};

    EXPECT_NO_THROW(contentRegister->changeSchedulerInterval(interval + 1));

    EXPECT_NO_THROW(contentModule.stop());
}
