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

#ifndef _CONTENT_REGISTER_TEST_HPP
#define _CONTENT_REGISTER_TEST_HPP

#include "gtest/gtest.h"
#include <external/nlohmann/json.hpp>

/**
 * @brief Runs component tests for ContentRegister
 */
class ContentRegisterTest : public ::testing::Test
{
protected:
    ContentRegisterTest() = default;
    ~ContentRegisterTest() override = default;

    nlohmann::json m_parameters;

    /**
     * @brief Sets initial conditions for each test case.
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_parameters = R"(
            {
                "topicName": "content-register-tests",
                "interval": 1,
                "ondemand": false,
                "configData": {
                    "contentSource": "api",
                    "compressionType": "raw",
                    "versionedContent": "false",
                    "deleteDownloadedContent": false,
                    "url": "https://swapi.dev/api/people/1",
                    "outputFolder": "/tmp/content-register-tests",
                    "dataFormat": "json",
                    "fileName": "sample1.json"
                }
            }
        )"_json;
    }
};

#endif //_CONTENT_REGISTER_TEST_HPP
