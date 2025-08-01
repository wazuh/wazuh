/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ichrome_extensions_wrapper.hpp"
#include "chrome_darwin.hpp"
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
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "darwin_mock_home");
    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillOnce(::testing::Return(mockHomePath));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(6));
}

TEST(ChromeExtensionsTests, CollectReturnsExpectedJson)
{
    auto mockExtensionsWrapper = std::make_shared<MockChromeExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "darwin_mock_home");
    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillOnce(::testing::Return(mockHomePath));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();

    EXPECT_EQ(extensionsJson[1]["author"], "");
    EXPECT_EQ(extensionsJson[1]["browser_type"], "chrome");
    EXPECT_EQ(extensionsJson[1]["current_locale"], "");
    EXPECT_EQ(extensionsJson[1]["default_locale"], "en");
    EXPECT_EQ(extensionsJson[1]["description"], "Chrome Web Store Payments");
    EXPECT_EQ(extensionsJson[1]["from_webstore"], "true");
    EXPECT_EQ(extensionsJson[1]["identifier"], "nmmhkkegccagdldgiimedpiccmgmieda");
    EXPECT_EQ(extensionsJson[1]["install_time"], "13394392373345452");
    EXPECT_EQ(extensionsJson[1]["install_timestamp"], "1749918773");
    EXPECT_EQ(extensionsJson[1]["manifest_hash"], "5dbdf0ed368be287abaff83d639b760fa5d7dc8a28e92387773b4fd3e1ba4f19");
    EXPECT_EQ(extensionsJson[1]["name"], "Chrome Web Store Payments");
    EXPECT_EQ(extensionsJson[1]["optional_permissions"], "");
    EXPECT_EQ(extensionsJson[1]["path"], Utils::joinPaths(mockHomePath, "mock-user/Library/Application Support/Google/Chrome/Profile 1/Extensions/nmmhkkegccagdldgiimedpiccmgmieda/1.0.0.6_0"));
    EXPECT_EQ(extensionsJson[1]["permissions"],
              "identity, webview, https://www.google.com/, https://www.googleapis.com/*, https://payments.google.com/payments/v4/js/integrator.js, https://sandbox.google.com/payments/v4/js/integrator.js");
    EXPECT_EQ(extensionsJson[1]["persistent"], "0");
    EXPECT_EQ(extensionsJson[1]["profile"], "Your Chrome");
    EXPECT_EQ(extensionsJson[1]["profile_path"], Utils::joinPaths(mockHomePath, "mock-user/Library/Application Support/Google/Chrome/Profile 1"));
    EXPECT_EQ(extensionsJson[1]["referenced"], "1");
    EXPECT_EQ(extensionsJson[1]["referenced_identifier"], "nmmhkkegccagdldgiimedpiccmgmieda");
    EXPECT_EQ(extensionsJson[1]["state"], "");
    EXPECT_EQ(extensionsJson[1]["uid"], "501");
    EXPECT_EQ(extensionsJson[1]["update_url"], "https://clients2.google.com/service/update2/crx");
    EXPECT_EQ(extensionsJson[1]["version"], "1.0.0.6");
}
