#include "ibrowser_extensions_wrapper.hpp"
#include "safari_darwin.hpp"
#include <string>
#include <filesystem>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <unistd.h>

class MockBrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        MOCK_METHOD(std::string, getApplicationsPath, (), (override));
};

TEST(BrowserExtensionsTests, IgnoresNonExtensionApp)
{
    auto mock_extensions_wrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::filesystem::path this_file_path(__FILE__);
    std::filesystem::path apps_path = this_file_path.parent_path() / std::filesystem::path("input_files/apps_mock_dir");
    EXPECT_CALL(*mock_extensions_wrapper, getApplicationsPath()).WillOnce(::testing::Return(apps_path.string()));

    BrowserExtensionsProvider browser_extensions_provider(mock_extensions_wrapper);
    nlohmann::json extensions_json = browser_extensions_provider.collect();

    // It should only detect 2 safari extensions.
    ASSERT_EQ(extensions_json.size(), static_cast<size_t>(2));
}

TEST(BrowserExtensionsTests, CollectReturnsExpectedJson)
{
    auto mock_extensions_wrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::filesystem::path this_file_path(__FILE__);
    std::filesystem::path apps_path = this_file_path.parent_path() / std::filesystem::path("input_files/apps_mock_dir");
    EXPECT_CALL(*mock_extensions_wrapper, getApplicationsPath()).WillOnce(::testing::Return(apps_path.string()));

    BrowserExtensionsProvider browser_extensions_provider(mock_extensions_wrapper);
    nlohmann::json extensions_json = browser_extensions_provider.collect();

    std::string uid_string = std::to_string(getuid());
    // The darker Info.plist file is in standard XML format
    std::filesystem::path darker_path = apps_path /
                                        std::filesystem::path("darker.app/Contents/PlugIns/darker Extension.appex/Contents/Info.plist");
    // The JSONPeep Info.plist file is in binary format
    std::filesystem::path json_peeps_path = apps_path /
                                            std::filesystem::path("JSONPeep.app/Contents/PlugIns/JSONPeep Extension.appex/Contents/Info.plist");
    // Testing darker extension
    EXPECT_EQ(extensions_json[0]["bundle_version"], "6");
    EXPECT_EQ(extensions_json[0]["copyright"], "");
    EXPECT_EQ(extensions_json[0]["description"], "");
    EXPECT_EQ(extensions_json[0]["identifier"], "com.doukan.darker.Extension");
    EXPECT_EQ(extensions_json[0]["name"], "darker Extension");
    EXPECT_EQ(extensions_json[0]["path"], darker_path.string());
    EXPECT_EQ(extensions_json[0]["sdk"], "6.0");
    EXPECT_EQ(extensions_json[0]["uid"], uid_string);
    EXPECT_EQ(extensions_json[0]["version"], "1.4");

    // Testing JSONPeep extension
    EXPECT_EQ(extensions_json[1]["bundle_version"], "13");
    EXPECT_EQ(extensions_json[1]["copyright"], "Copyright © 2019 Lev Bruk. All rights reserved.");
    EXPECT_EQ(extensions_json[1]["description"], "A Safari Extension to view JSON in a readable format. Smooth and simple. Nothing more.");
    EXPECT_EQ(extensions_json[1]["identifier"], "com.levbruk.JSONPeep.Extension");
    EXPECT_EQ(extensions_json[1]["name"], "JSON Peep");
    EXPECT_EQ(extensions_json[1]["path"], json_peeps_path.string());
    EXPECT_EQ(extensions_json[1]["sdk"], "6.0");
    EXPECT_EQ(extensions_json[1]["uid"], uid_string);
    EXPECT_EQ(extensions_json[1]["version"], "1.3.2");
}
