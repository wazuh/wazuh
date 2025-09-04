#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy.hpp>
#include <sca_policy_loader.hpp>
#include <sca_policy_loader_mock.hpp>
#include <sca_policy_parser.hpp>

#include "logging_helper.hpp"

#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>

#include <memory>

class ScaPolicyLoaderTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t, const char*)
            {
                // noop
            });

            mockFileSystem = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
            mockDBSync = std::make_shared<testing::NiceMock<MockDBSync>>();
        }

        std::shared_ptr<MockFileSystemWrapper> mockFileSystem;
        std::shared_ptr<MockDBSync> mockDBSync;
};

TEST_F(ScaPolicyLoaderTest, ConstructionNoPolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    const SCAPolicyLoader loader({}, fsMock);
    SUCCEED();
}

TEST_F(ScaPolicyLoaderTest, ConstructionSomePolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();

    std::vector<sca::PolicyData> policies { {"dummy/path/1", true, false},
        {"dummy/path/2", true, false},
        {"dummy/path/3", true, false},
        {"dummy/path/4", false, false}};

    const SCAPolicyLoader loader(policies, fsMock);
    SUCCEED();
}

TEST_F(ScaPolicyLoaderTest, LoadPoliciesSkipsDisabledPolicies)
{
    std::vector<sca::PolicyData> policies =
    {
        {"policy1.yaml", false, false},  // Disabled
        {"policy2.yaml", true, false}    // Enabled
    };

    EXPECT_CALL(*mockFileSystem, exists(testing::_))
    .WillOnce(testing::Return(true))  // Only check enabled policy
    .WillOnce(testing::Return(true));

    SCAPolicyLoader loader(policies, mockFileSystem, mockDBSync);

    auto mockYamlToJson = [](const std::string&) -> nlohmann::json { return nlohmann::json{}; };
    auto loadedPolicies = loader.LoadPolicies(30, true, [](auto, auto) {}, mockYamlToJson);
    EXPECT_LE(loadedPolicies.size(), 1);  // Should only load enabled policy
}

TEST_F(ScaPolicyLoaderTest, LoadPoliciesNoPolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    const SCAPolicyLoader loader({}, fsMock, dbSync);
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json { return nlohmann::json{}; };
    ASSERT_EQ(loader.LoadPolicies(30, true, [](auto, auto)
    {
        return;
    }, mockYamlToJson).size(), 0);
}

TEST_F(ScaPolicyLoaderTest, LoadPoliciesSomePolicies)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    MockFileSystemWrapper* m_rawFsMock = fsMock.get();

    EXPECT_CALL(*m_rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path&)
    {
        return true;
    });

    auto dbSync = std::make_shared<MockDBSync>();

    std::vector<sca::PolicyData> policies { {"dummy/path/1", true, false},
        {"dummy/path/2", true, false},
        {"dummy/path/3", true, false},
        {"dummy/path/4", false, false}};

    const SCAPolicyLoader loader(policies, fsMock, dbSync);
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json { return nlohmann::json{}; };
    ASSERT_EQ(loader.LoadPolicies(30, true, [](auto, auto)
    {
        return;
    }, mockYamlToJson).size(), 0);
}

TEST_F(ScaPolicyLoaderTest, SyncPoliciesAndReportDeltaBadData)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    MockFileSystemWrapper* m_rawFsMock = fsMock.get();

    EXPECT_CALL(*m_rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path&)
    {
        return true;
    });

    const std::string yml = R"(
      novariables:
        $var1: /etc
        $var11: /usr
      nopolicy:
        id: policy1
      nochecks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    // create a yaml to json function for the parser
    auto yamlToJsonFunc = [yml](const std::string&) -> nlohmann::json
    {
        // For test purposes, manually convert the YAML structure to JSON
        // This is a simplified conversion for the specific test content
        nlohmann::json result;

        if (yml.find("novariables:") != std::string::npos)
        {
            // Handle malformed YAML case
            result["novariables"] = {{"$var1", "/etc"}, {"$var11", "/usr"}};
            result["nopolicy"] = {{"id", "policy1"}};
            result["nochecks"] = nlohmann::json::array(
            {
                {   {"id", "check1"}, {"title", "title"}, {"condition", "all"},
                    {"rules", {"f: $var1/passwd exists", "f: $var11/shared exists"}}
                }
            });
        }
        else if (yml.find("variables:") != std::string::npos)
        {
            // Handle well-formed YAML case
            result["variables"] = {{"$var1", "/etc"}, {"$var11", "/usr"}};
            result["policy"] = {{"id", "policy1"}};
            result["checks"] = nlohmann::json::array(
            {
                {   {"id", "check1"}, {"title", "title"}, {"condition", "all"},
                    {"rules", {"f: $var1/passwd exists", "f: $var11/shared exists"}}
                }
            });

            if (yml.find("check2") != std::string::npos)
            {
                result["checks"].push_back({{"id", "check2"}, {"title", "title2"}, {"condition", "any"},
                    {"rules", {"f: $var1/passwd2 exists", "f: $var11/shared2 exists"}}});
            }
        }

        return result;
    };
    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, yamlToJsonFunc);

    // parse this policy and get a real policy object
    nlohmann::json jasonData;
    const auto policyOpt = parser.ParsePolicy(jasonData);
    ASSERT_FALSE(policyOpt);

    const SCAPolicyLoader loader({}, fsMock, dbSync);

    loader.SyncPoliciesAndReportDelta(jasonData, [](auto, auto)
    {
        return;
    });
    SUCCEED();
}


TEST_F(ScaPolicyLoaderTest, SyncPoliciesAndReportDeltaNoDBSyncObject)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    MockFileSystemWrapper* m_rawFsMock = fsMock.get();

    EXPECT_CALL(*m_rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path&)
    {
        return true;
    });

    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
        - id: check2
          title: "title2"
          condition: "any"
          rules:
            - 'f: $var1/passwd2 exists'
            - 'f: $var11/shared2 exists'
      )";

    // create a yaml to json function for the parser
    auto yamlToJsonFunc = [yml](const std::string&) -> nlohmann::json
    {
        // For test purposes, manually convert the YAML structure to JSON
        // This is a simplified conversion for the specific test content
        nlohmann::json result;

        if (yml.find("novariables:") != std::string::npos)
        {
            // Handle malformed YAML case
            result["novariables"] = {{"$var1", "/etc"}, {"$var11", "/usr"}};
            result["nopolicy"] = {{"id", "policy1"}};
            result["nochecks"] = nlohmann::json::array(
            {
                {   {"id", "check1"}, {"title", "title"}, {"condition", "all"},
                    {"rules", {"f: $var1/passwd exists", "f: $var11/shared exists"}}
                }
            });
        }
        else if (yml.find("variables:") != std::string::npos)
        {
            // Handle well-formed YAML case
            result["variables"] = {{"$var1", "/etc"}, {"$var11", "/usr"}};
            result["policy"] = {{"id", "policy1"}};
            result["checks"] = nlohmann::json::array(
            {
                {   {"id", "check1"}, {"title", "title"}, {"condition", "all"},
                    {"rules", {"f: $var1/passwd exists", "f: $var11/shared exists"}}
                }
            });

            if (yml.find("check2") != std::string::npos)
            {
                result["checks"].push_back({{"id", "check2"}, {"title", "title2"}, {"condition", "any"},
                    {"rules", {"f: $var1/passwd2 exists", "f: $var11/shared2 exists"}}});
            }
        }

        return result;
    };
    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, yamlToJsonFunc);

    // parse this policy and get a real policy object
    nlohmann::json jasonData;
    const auto policyOpt = parser.ParsePolicy(jasonData);
    ASSERT_TRUE(policyOpt);

    const SCAPolicyLoader loader({}, fsMock, nullptr);

    loader.SyncPoliciesAndReportDelta(jasonData, [](auto, auto)
    {
        return;
    });
    SUCCEED();
}


TEST_F(ScaPolicyLoaderTest, SyncPoliciesAndReportDelta)
{
    auto fsMock = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto dbSync = std::make_shared<MockDBSync>();

    MockFileSystemWrapper* rawFsMock = fsMock.get();
    MockDBSync* rawDbSyncMock = dbSync.get();

    EXPECT_CALL(*rawFsMock, exists(::testing::_))
    .Times(::testing::AnyNumber())
    .WillRepeatedly([](const std::filesystem::path&)
    {
        return true;
    });

    EXPECT_CALL(*rawDbSyncMock, handle())
    .Times(::testing::AnyNumber())
    .WillRepeatedly([]()-> void*
    {
        return nullptr;
    });


    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    // create a yaml to json function for the parser
    auto yamlToJsonFunc = [yml](const std::string&) -> nlohmann::json
    {
        // For test purposes, manually convert the YAML structure to JSON
        // This is a simplified conversion for the specific test content
        nlohmann::json result;

        if (yml.find("novariables:") != std::string::npos)
        {
            // Handle malformed YAML case
            result["novariables"] = {{"$var1", "/etc"}, {"$var11", "/usr"}};
            result["nopolicy"] = {{"id", "policy1"}};
            result["nochecks"] = nlohmann::json::array(
            {
                {   {"id", "check1"}, {"title", "title"}, {"condition", "all"},
                    {"rules", {"f: $var1/passwd exists", "f: $var11/shared exists"}}
                }
            });
        }
        else if (yml.find("variables:") != std::string::npos)
        {
            // Handle well-formed YAML case
            result["variables"] = {{"$var1", "/etc"}, {"$var11", "/usr"}};
            result["policy"] = {{"id", "policy1"}};
            result["checks"] = nlohmann::json::array(
            {
                {   {"id", "check1"}, {"title", "title"}, {"condition", "all"},
                    {"rules", {"f: $var1/passwd exists", "f: $var11/shared exists"}}
                }
            });

            if (yml.find("check2") != std::string::npos)
            {
                result["checks"].push_back({{"id", "check2"}, {"title", "title2"}, {"condition", "any"},
                    {"rules", {"f: $var1/passwd2 exists", "f: $var11/shared2 exists"}}});
            }
        }

        return result;
    };
    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, yamlToJsonFunc);

    // parse this policy and get a real policy object
    nlohmann::json jasonData;
    const auto policyOpt = parser.ParsePolicy(jasonData);
    ASSERT_TRUE(policyOpt);

    const SCAPolicyLoader loader({}, fsMock, dbSync);

    loader.SyncPoliciesAndReportDelta(jasonData, [](auto, auto)
    {
        return;
    });
    SUCCEED();
}

TEST_F(ScaPolicyLoaderTest, NormalizeData_EmptyInput)
{
    ScaPolicyLoaderMock policyLoader;
    nlohmann::json input = nlohmann::json::array();
    auto result = policyLoader.NormalizeData(input);

    EXPECT_TRUE(result.is_array());
    EXPECT_TRUE(result.empty());
}

TEST_F(ScaPolicyLoaderTest, NormalizeData_NoTransformationsNeeded)
{
    ScaPolicyLoaderMock policyLoader;

    nlohmann::json input =
    {
        {
            {"id", "test1"},
            {"name", "Test Name"},
            {"refs", "reference1,reference2"},
            {"description", "Test description"}
        },
        {
            {"id", "test2"},
            {"name", "Test Name 2"},
            {"refs", "reference3"},
            {"other_field", "value"}
        }
    };

    auto result = policyLoader.NormalizeData(input);

    EXPECT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 2);

    // Should remain unchanged
    EXPECT_EQ(result[0]["id"], "test1");
    EXPECT_EQ(result[0]["name"], "Test Name");
    EXPECT_EQ(result[0]["refs"], "reference1,reference2");
    EXPECT_EQ(result[1]["id"], "test2");
    EXPECT_EQ(result[1]["name"], "Test Name 2");
}

TEST_F(ScaPolicyLoaderTest, NormalizeDataWithChecksum_PolicyTable_NoChecksum)
{
    ScaPolicyLoaderMock policyLoader;

    nlohmann::json input =
    {
        {
            {"id", "policy1"},
            {"title", "Test Policy"},
            {"references", "ref1,ref2"},
            {"description", "Test description"}
        }
    };

    auto result = policyLoader.NormalizeDataWithChecksum(input, SCA_POLICY_TABLE_NAME);

    EXPECT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 1);

    // Should have transformations but no checksum
    EXPECT_FALSE(result[0].contains("title"));
    EXPECT_FALSE(result[0].contains("references"));
    EXPECT_TRUE(result[0].contains("name"));
    EXPECT_TRUE(result[0].contains("refs"));
    EXPECT_FALSE(result[0].contains("checksum"));
    EXPECT_EQ(result[0]["name"], "Test Policy");
    EXPECT_EQ(result[0]["refs"], "\"ref1,ref2\"");
}

TEST_F(ScaPolicyLoaderTest, NormalizeDataWithChecksum_CheckTable_AddsChecksum)
{
    ScaPolicyLoaderMock policyLoader;

    nlohmann::json input =
    {
        {
            {"id", "check1"},
            {"title", "Test Check"},
            {"references", "ref1"},
            {"policy_id", "policy1"},
            {"description", "Test check description"}
        }
    };

    auto result = policyLoader.NormalizeDataWithChecksum(input, SCA_CHECK_TABLE_NAME);

    EXPECT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 1);

    // Should have transformations AND checksum
    EXPECT_FALSE(result[0].contains("title"));
    EXPECT_FALSE(result[0].contains("references"));
    EXPECT_TRUE(result[0].contains("name"));
    EXPECT_TRUE(result[0].contains("refs"));
    EXPECT_TRUE(result[0].contains("checksum"));
    EXPECT_EQ(result[0]["name"], "Test Check");
    EXPECT_EQ(result[0]["refs"], "\"ref1\"");

    EXPECT_TRUE(result[0]["checksum"].is_string());
    EXPECT_FALSE(result[0]["checksum"].get<std::string>().empty());
}

TEST_F(ScaPolicyLoaderTest, NormalizeDataWithChecksum_EmptyCheckTable)
{
    ScaPolicyLoaderMock policyLoader;
    nlohmann::json input = nlohmann::json::array();
    auto result = policyLoader.NormalizeDataWithChecksum(input, SCA_CHECK_TABLE_NAME);

    EXPECT_TRUE(result.is_array());
    EXPECT_TRUE(result.empty());
}

TEST_F(ScaPolicyLoaderTest, NormalizeDataWithChecksum_EmptyPolicyTable)
{
    ScaPolicyLoaderMock policyLoader;
    nlohmann::json input = nlohmann::json::array();

    auto result = policyLoader.NormalizeDataWithChecksum(input, SCA_POLICY_TABLE_NAME);

    EXPECT_TRUE(result.is_array());
    EXPECT_TRUE(result.empty());
}

TEST_F(ScaPolicyLoaderTest, UpdateCheckResult_NullDBSync)
{
    ScaPolicyLoaderMock nullLoader;

    nlohmann::json check =
    {
        {"id", "check1"},
        {"result", "passed"}
    };

    // Should not crash and should log error
    EXPECT_NO_THROW(
    {
        nullLoader.UpdateCheckResult(check);
    });
}


TEST_F(ScaPolicyLoaderTest, UpdateCheckResult_ValidCheck)
{
    ScaPolicyLoaderMock nullLoader(mockDBSync);
    nlohmann::json check =
    {
        {"id", "check1"},
        {"policy_id", "policy1"},
        {"name", "Test Check"},
        {"result", "passed"},
        {"description", "Test description"}
    };

    EXPECT_CALL(*mockDBSync, syncRow(testing::_, testing::_))
    .WillOnce([](const nlohmann::json&,
                 const std::function<void(ReturnTypeCallback, const nlohmann::json&)>& callback)
    {
        callback(INSERTED, nlohmann::json::object());
    });

    EXPECT_NO_THROW(
    {
        nullLoader.UpdateCheckResult(check);
    });
}
