/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ichrome_extensions_wrapper.hpp"
#include "chrome_linux.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class MockChromeExtensionsWrapper : public IChromeExtensionsWrapper
{
    public:
        MOCK_METHOD(std::filesystem::path, getHomePath, (), (override));
};

TEST(ChromeExtensionsTests, NumberOfExtensions)
{
    auto mockExtensionsWrapper = std::make_shared<MockChromeExtensionsWrapper>();
    std::filesystem::path mockHomePath = std::filesystem::path(__FILE__).parent_path() / "mock_home";
    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillOnce(::testing::Return(mockHomePath));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();

    // It should only detect 2 safari extensions.
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(6));
}
