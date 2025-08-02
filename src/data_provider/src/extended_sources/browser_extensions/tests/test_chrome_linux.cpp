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
#include "filesystemHelper.h"

class MockChromeExtensionsWrapper : public IChromeExtensionsWrapper
{
    public:
        MOCK_METHOD(std::string, getHomePath, (), (override));
};

TEST(ChromeExtensionsTests, NumberOfExtensions)
{
    auto mockExtensionsWrapper = std::make_shared<MockChromeExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "mock_home");
    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillOnce(::testing::Return(mockHomePath));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();

    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(6));
}

TEST(ChromeExtensionsTests, CollectReturnsExpectedJson)
{
    auto mockExtensionsWrapper = std::make_shared<MockChromeExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "mock_home");
    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillOnce(::testing::Return(mockHomePath));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();

    EXPECT_EQ(extensionsJson[2]["author"], "");
    EXPECT_EQ(extensionsJson[2]["browser_type"], "chrome");
    EXPECT_EQ(extensionsJson[2]["current_locale"], "");
    EXPECT_EQ(extensionsJson[2]["default_locale"], "en");
    EXPECT_EQ(extensionsJson[2]["description"], "Chrome Web Store Payments");
    EXPECT_EQ(extensionsJson[2]["from_webstore"], "true");
    EXPECT_EQ(extensionsJson[2]["identifier"], "nmmhkkegccagdldgiimedpiccmgmieda");
    EXPECT_EQ(extensionsJson[2]["install_time"], "13394392320846794");
    EXPECT_EQ(extensionsJson[2]["install_timestamp"], "1749918720");
    EXPECT_EQ(extensionsJson[2]["manifest_hash"], "5dbdf0ed368be287abaff83d639b760fa5d7dc8a28e92387773b4fd3e1ba4f19");
    EXPECT_EQ(extensionsJson[2]["name"], "Chrome Web Store Payments");
    EXPECT_EQ(extensionsJson[2]["optional_permissions"], "");
    EXPECT_EQ(extensionsJson[2]["path"], Utils::joinPaths(mockHomePath, "mock-user/.config/google-chrome/Default/Extensions/nmmhkkegccagdldgiimedpiccmgmieda/1.0.0.6_0"));
    EXPECT_EQ(extensionsJson[2]["permissions"],
              "identity, webview, https://www.google.com/, https://www.googleapis.com/*, https://payments.google.com/payments/v4/js/integrator.js, https://sandbox.google.com/payments/v4/js/integrator.js");
    EXPECT_EQ(extensionsJson[2]["persistent"], "0");
    EXPECT_EQ(extensionsJson[2]["profile"], "Your Chrome");
    EXPECT_EQ(extensionsJson[2]["profile_path"], Utils::joinPaths(mockHomePath, "mock-user/.config/google-chrome/Default"));
    EXPECT_EQ(extensionsJson[2]["referenced"], "1");
    EXPECT_EQ(extensionsJson[2]["referenced_identifier"], "nmmhkkegccagdldgiimedpiccmgmieda");
    EXPECT_EQ(extensionsJson[2]["state"], "");
    EXPECT_EQ(extensionsJson[2]["uid"], "1000");
    EXPECT_EQ(extensionsJson[2]["update_url"], "https://clients2.google.com/service/update2/crx");
    EXPECT_EQ(extensionsJson[2]["version"], "1.0.0.6");
}
