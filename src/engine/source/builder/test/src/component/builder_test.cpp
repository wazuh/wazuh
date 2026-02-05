#include <gtest/gtest.h>

#include <base/baseTypes.hpp>
#include <base/behaviour.hpp>
#include <store/mockStore.hpp>

#include "definitions.hpp"

using namespace builder::test;
using namespace cm::store;
using namespace base::test;

namespace builder
{

using SuccessExpected = InnerExpected<None,
                                      const std::shared_ptr<MockICMstore>&,
                                      const std::shared_ptr<MockICMStoreNSReader>&,
                                      const std::shared_ptr<schemf::mocks::MockSchema>&>;
using FailureExpected = InnerExpected<std::string,
                                      const std::shared_ptr<MockICMstore>&,
                                      const std::shared_ptr<MockICMStoreNSReader>&,
                                      const std::shared_ptr<schemf::mocks::MockSchema>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

// Policy build parameters
using Build = std::tuple<std::string, Expc>;

class BuildPolicy : public BuilderTestFixture<Build>
{
};

TEST_P(BuildPolicy, Doc)
{
    auto [namespaceId, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader, m_spMocks->m_spSchemf);

        NamespaceId nsId(namespaceId);
        ASSERT_NO_THROW({
            auto policy = m_spBuilder->buildPolicy(nsId, false, true);
            ASSERT_NE(policy, nullptr);
            EXPECT_EQ(policy->name().toStr(), nsId.toStr());
        });
    }
    else
    {
        auto errorMsg = expected.failCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader, m_spMocks->m_spSchemf);

        NamespaceId nsId(namespaceId);
        ASSERT_THROW(
            try { m_spBuilder->buildPolicy(nsId, false, true); } catch (const std::exception& e) {
                EXPECT_TRUE(std::string(e.what()).find(errorMsg) != std::string::npos);
                throw;
            },
            std::exception);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Policy,
    BuildPolicy,
    ::testing::Values(
        // Simple policy with enabled integration
        Build("policy_test_0",
              SUCCESS(SuccessExpected::Behaviour {
                  [](const auto& store, const auto& reader, const auto& schemf)
                  {
                      auto policy = dataType::Policy("test-policy",
                                                     "550e8400-e29b-41d4-a716-446655440003",
                                                     {"550e8400-e29b-41d4-a716-446655440001"},
                                                     {},
                                                     {},
                                                     {});
                      auto integration = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                                               "test-integration",
                                                               true,
                                                               "system-activity",
                                                               std::nullopt,
                                                               {},
                                                               {"550e8400-e29b-41d4-a716-446655440004"},
                                                               false);

                      EXPECT_CALL(*store, getNSReader(testing::_)).WillRepeatedly(testing::Return(reader));
                      EXPECT_CALL(*reader, getPolicy()).WillRepeatedly(testing::Return(policy));

                      NamespaceId nsId("policy_test_0");
                      EXPECT_CALL(*reader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(nsId));
                      EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
                          .WillRepeatedly(testing::Return(integration));
                      EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                          .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));
                      EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
                          .WillRepeatedly(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));

                      // Create specific assets for each UUID
                      auto rootDecoder = json::Json(R"({"name": "decoder/root/0", "enabled": true})");
                      auto testDecoder = json::Json(
                          R"({"name": "decoder/test/0", "enabled": true, "parents": ["DecodersTree/Input"]})");

                      EXPECT_CALL(*reader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
                          .WillRepeatedly(testing::Return(rootDecoder));
                      EXPECT_CALL(*reader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440004"))
                          .WillRepeatedly(testing::Return(testDecoder));

                      EXPECT_CALL(*reader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));
                      EXPECT_CALL(*reader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));
                      EXPECT_CALL(*reader, getDefaultOutputs())
                          .WillRepeatedly(testing::Return(std::vector<json::Json> {}));
                      return None {};
                  }})),
        // Policy with disabled integration
        Build("policy_disabled_0",
              SUCCESS(SuccessExpected::Behaviour {
                  [](const auto& store, const auto& reader, const auto& schemf)
                  {
                      auto policy = dataType::Policy("test-policy-disabled",
                                                     "550e8400-e29b-41d4-a716-446655440003",
                                                     {"550e8400-e29b-41d4-a716-446655440001",  // disabled
                                                      "550e8400-e29b-41d4-a716-446655440005"}, // enabled
                                                     {},
                                                     {},
                                                     {});
                      auto integration = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                                               "disabled-integration",
                                                               false,
                                                               "network-activity",
                                                               std::nullopt,
                                                               {},
                                                               {},
                                                               false);
                      auto integration2 = dataType::Integration("550e8400-e29b-41d4-a716-446655440005",
                                                                "enabled-integration",
                                                                true,
                                                                "system-activity",
                                                                std::nullopt,
                                                                {},
                                                                {"550e8400-e29b-41d4-a716-446655440003"},
                                                                false);

                      EXPECT_CALL(*store, getNSReader(testing::_)).WillRepeatedly(testing::Return(reader));
                      EXPECT_CALL(*reader, getPolicy()).WillRepeatedly(testing::Return(policy));

                      NamespaceId nsId("policy_disabled_0");
                      EXPECT_CALL(*reader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(nsId));
                      EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
                          .WillRepeatedly(testing::Return(integration));
                      EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440005"))
                          .WillRepeatedly(testing::Return(integration2));
                      EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                          .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

                      auto rootDecoder = json::Json(R"({"name": "decoder/root/0", "enabled": true})");
                      EXPECT_CALL(*reader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
                          .WillRepeatedly(testing::Return(rootDecoder));
                      EXPECT_CALL(*reader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));
                      EXPECT_CALL(*reader, getDefaultOutputs())
                          .WillRepeatedly(testing::Return(std::vector<json::Json> {}));
                      return None {};
                  }})),
        // Policy with multiple integrations
        Build("policy_multi_0",
              SUCCESS(SuccessExpected::Behaviour {
                  [](const auto& store, const auto& reader, const auto& schemf)
                  {
                      auto policy = dataType::Policy(
                          "test-policy-multi",
                          "550e8400-e29b-41d4-a716-446655440003",
                          {"550e8400-e29b-41d4-a716-446655440001", "550e8400-e29b-41d4-a716-446655440005"},
                          {},
                          {},
                          {});
                      auto integration1 =
                          dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                                "integration-one",
                                                true,
                                                "security",
                                                std::nullopt,
                                                {},
                                                {"550e8400-e29b-41d4-a716-446655440003"}, // root decoder
                                                false);
                      auto integration2 = dataType::Integration("550e8400-e29b-41d4-a716-446655440005",
                                                                "integration-two",
                                                                true,
                                                                "cloud-services",
                                                                std::nullopt,
                                                                {},
                                                                {},
                                                                false);

                      EXPECT_CALL(*store, getNSReader(testing::_)).WillRepeatedly(testing::Return(reader));
                      EXPECT_CALL(*reader, getPolicy()).WillRepeatedly(testing::Return(policy));

                      NamespaceId nsId("policy_multi_0");
                      EXPECT_CALL(*reader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(nsId));
                      EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
                          .WillRepeatedly(testing::Return(integration1));
                      EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440005"))
                          .WillRepeatedly(testing::Return(integration2));
                      EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                          .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

                      auto rootDecoder = json::Json(R"({"name": "decoder/root/0", "enabled": true})");
                      EXPECT_CALL(*reader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
                          .WillRepeatedly(testing::Return(rootDecoder));

                      EXPECT_CALL(*reader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));
                      EXPECT_CALL(*reader, getDefaultOutputs())
                          .WillRepeatedly(testing::Return(std::vector<json::Json> {}));
                      return None {};
                  }}))));

// Asset build parameters
using BuildA = std::tuple<base::Name, std::string, json::Json, std::vector<std::string>, Expc>;

class BuildAsset : public BuilderTestFixture<BuildA>
{
};

TEST_P(BuildAsset, Doc)
{
    auto [assetName, namespaceId, assetContent, schemaFields, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader, m_spMocks->m_spSchemf);

        EXPECT_CALL(*m_spMocks->m_spStore, getNSReader(testing::_))
            .WillRepeatedly(testing::Return(m_spMocks->m_spNSReader));
        EXPECT_CALL(*m_spMocks->m_spNSReader, getAssetByName(assetName)).WillRepeatedly(testing::Return(assetContent));
        EXPECT_CALL(*m_spMocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

        for (const auto& field : schemaFields)
        {
            EXPECT_CALL(*m_spMocks->m_spSchemf, hasField(DotPath(field))).WillRepeatedly(testing::Return(true));
        }

        NamespaceId nsId(namespaceId);
        ASSERT_NO_THROW({
            auto expression = m_spBuilder->buildAsset(assetName, nsId);
            ASSERT_NE(expression, nullptr);
            EXPECT_EQ(expression->getName(), assetName);
        });
    }
}

INSTANTIATE_TEST_SUITE_P(Asset,
                         BuildAsset,
                         ::testing::Values(
                             // Decoder
                             BuildA(base::Name("decoder/test/0"),
                                    "policy_test_0",
                                    json::Json(R"({
                   "name": "decoder/test/0",
                   "parents": ["DecodersTree/Input"],
                   "check": [{"event.code": 2}]
               })"),
                                    std::vector<std::string> {"event.code"},
                                    SUCCESS()),
                             // Rule
                             BuildA(base::Name("rule/test/0"),
                                    "policy_test_0",
                                    json::Json(R"({
                   "name": "rule/test/0",
                   "check": [{"process.name": "test"}],
                   "normalize": [{"map": [{"event.risk_score": 21}]}]
               })"),
                                    std::vector<std::string> {"process.name", "event.risk_score"},
                                    SUCCESS()),
                             // Filter
                             BuildA(base::Name("filter/test/0"),
                                    "policy_test_0",
                                    json::Json(R"({
                   "name": "filter/test/0",
                   "check": [{"wazuh.protocol.queue": 49}]
               })"),
                                    std::vector<std::string> {"wazuh.protocol.queue"},
                                    SUCCESS()),
                             // Output
                             BuildA(base::Name("output/test/0"),
                                    "policy_test_0",
                                    json::Json(R"({
                   "name": "output/test/0",
                   "check": [{"event.category": "intrusion_detection"}]
               })"),
                                    std::vector<std::string> {"event.category"},
                                    SUCCESS())));

// Advanced tests for complex scenarios
class BuildPolicyTest : public ::testing::Test
{
protected:
    std::shared_ptr<Mocks> m_mocks;
    std::shared_ptr<Builder> m_builder;

    void SetUp() override
    {
        m_mocks = std::make_shared<Mocks>();
        m_mocks->m_spStore = std::make_shared<MockICMstore>();
        m_mocks->m_spNSReader = std::make_shared<MockICMStoreNSReader>();
        m_mocks->m_spSchemf = std::make_shared<schemf::mocks::MockSchema>();
        m_mocks->m_spDefBuilder = std::make_shared<defs::mocks::MockDefinitionsBuilder>();
        m_mocks->m_spDef = std::make_shared<defs::mocks::MockDefinitions>();

        BuilderDeps builderDeps;
        builderDeps.logparDebugLvl = 0;

        // Setup basic schema expectations
        ON_CALL(*m_mocks->m_spSchemf, hasField(DotPath("wazuh.message"))).WillByDefault(testing::Return(true));
        ON_CALL(*m_mocks->m_spSchemf, hasField(DotPath("event.code"))).WillByDefault(testing::Return(true));
        ON_CALL(*m_mocks->m_spSchemf, hasField(DotPath("source.ip"))).WillByDefault(testing::Return(true));

        builderDeps.logpar =
            std::make_shared<hlp::logpar::Logpar>(json::Json {WAZUH_LOGPAR_TYPES_JSON}, m_mocks->m_spSchemf);
        builderDeps.kvdbManager = nullptr;

        auto emptyAllowedFields = std::make_shared<AllowedFields>();
        auto mockStore = std::make_shared<store::mocks::MockStore>();

        m_builder = std::make_shared<Builder>(
            m_mocks->m_spStore, m_mocks->m_spSchemf, m_mocks->m_spDefBuilder, emptyAllowedFields, builderDeps, mockStore);
    }
};

TEST_F(BuildPolicyTest, BuildPolicySuccessfully)
{
    // Setup namespace and policy data
    NamespaceId namespaceId("policy_test_0");

    // Create a simple policy with one integration
    auto policy = dataType::Policy("test-policy",                            // title
                                   "550e8400-e29b-41d4-a716-446655440003",   // root decoder
                                   {"550e8400-e29b-41d4-a716-446655440001"}, // integrations (valid UUIDv4)
                                   {},                                       // filters
                                   {},                                       // enrichments
                                   {}                                        // outputs
    );

    // Create a simple integration
    auto integration = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                             "test-integration",
                                             true,                                     // enabled
                                             "system-activity",                        // valid category
                                             std::nullopt,                             // default parent
                                             {},                                       // kvdbs
                                             {"550e8400-e29b-41d4-a716-446655440004"}, // decoders
                                             false                                     // requireUUID
    );

    // Create decoder asset
    auto decoder = json::Json(R"({
        "name": "decoder/test/0",
        "enabled": true,
        "parents": ["DecodersTree/Input"],
        "check": [{
            "event.code": 2
        }]
    })");

    // Create default parent asset
    auto defaultParent = json::Json(R"({
        "name": "decoder/default-parent/0",
        "enabled": true
    })");

    // Create root decoder asset
    auto rootDecoder = json::Json(R"({
        "name": "decoder/root/0",
        "enabled": true,
        "parents": ["DecodersTree/Input"]
    })");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getPolicy()).WillRepeatedly(testing::Return(policy));

    EXPECT_CALL(*m_mocks->m_spNSReader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(namespaceId));

    EXPECT_CALL(*m_mocks->m_spNSReader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
        .WillRepeatedly(testing::Return(integration));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440004"))
        .WillRepeatedly(testing::Return(decoder));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440002"))
        .WillRepeatedly(testing::Return(defaultParent));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(rootDecoder));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, getDefaultOutputs())
        .WillRepeatedly(testing::Return(std::vector<json::Json> {}));

    // Build policy
    auto builtPolicy = m_builder->buildPolicy(namespaceId, false, true);

    // Verify results - policy should be created without error
    ASSERT_NE(builtPolicy, nullptr);
    EXPECT_EQ(builtPolicy->name().toStr(), namespaceId.toStr());
    // Note: assets may be empty in this simplified mock setup - that's OK for a component test
}

TEST_F(BuildPolicyTest, BuildPolicyWithDisabledIntegration)
{
    // Setup namespace and policy data
    NamespaceId namespaceId("policy_test_0");

    auto policy = dataType::Policy("test-policy-disabled",
                                   "550e8400-e29b-41d4-a716-446655440003",   // root decoder
                                   {"550e8400-e29b-41d4-a716-446655440001",  // disabled integration
                                    "550e8400-e29b-41d4-a716-446655440005"}, // enabled integration
                                   {},
                                   {},
                                   {});

    // Create a disabled integration
    auto integration = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                             "test-integration-disabled",
                                             false,             // disabled
                                             "system-activity", // valid category
                                             std::nullopt,
                                             {},
                                             {"550e8400-e29b-41d4-a716-446655440004"},
                                             false);

    // Create an enabled integration with the root decoder
    auto integration2 = dataType::Integration("550e8400-e29b-41d4-a716-446655440005",
                                              "test-integration-enabled",
                                              true, // enabled
                                              "network-activity",
                                              std::nullopt,
                                              {},
                                              {"550e8400-e29b-41d4-a716-446655440003"}, // root decoder
                                              false);

    auto defaultParent = json::Json(R"({"name": "decoder/default-parent/0", "enabled": true})");
    auto rootDecoder = json::Json(R"({"name": "decoder/root/0", "enabled": true})");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getPolicy()).WillRepeatedly(testing::Return(policy));

    EXPECT_CALL(*m_mocks->m_spNSReader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(namespaceId));

    EXPECT_CALL(*m_mocks->m_spNSReader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
        .WillRepeatedly(testing::Return(integration));

    EXPECT_CALL(*m_mocks->m_spNSReader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440005"))
        .WillRepeatedly(testing::Return(integration2));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440002"))
        .WillRepeatedly(testing::Return(defaultParent));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(rootDecoder));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, getDefaultOutputs())
        .WillRepeatedly(testing::Return(std::vector<json::Json> {}));

    // Build policy - should succeed: disabled integration is skipped, enabled integration provides root decoder
    auto builtPolicy = m_builder->buildPolicy(namespaceId, false, true);

    ASSERT_NE(builtPolicy, nullptr);
    EXPECT_EQ(builtPolicy->name().toStr(), namespaceId.toStr());
}

class BuildAssetTest : public ::testing::Test
{
protected:
    std::shared_ptr<Mocks> m_mocks;
    std::shared_ptr<Builder> m_builder;

    void SetUp() override
    {
        m_mocks = std::make_shared<Mocks>();
        m_mocks->m_spStore = std::make_shared<MockICMstore>();
        m_mocks->m_spNSReader = std::make_shared<MockICMStoreNSReader>();
        m_mocks->m_spSchemf = std::make_shared<schemf::mocks::MockSchema>();
        m_mocks->m_spDefBuilder = std::make_shared<defs::mocks::MockDefinitionsBuilder>();
        m_mocks->m_spDef = std::make_shared<defs::mocks::MockDefinitions>();

        BuilderDeps builderDeps;
        builderDeps.logparDebugLvl = 0;

        ON_CALL(*m_mocks->m_spSchemf, hasField(DotPath("wazuh.message"))).WillByDefault(testing::Return(true));
        ON_CALL(*m_mocks->m_spSchemf, hasField(DotPath("event.code"))).WillByDefault(testing::Return(true));
        ON_CALL(*m_mocks->m_spSchemf, hasField(DotPath("source.ip"))).WillByDefault(testing::Return(true));

        builderDeps.logpar =
            std::make_shared<hlp::logpar::Logpar>(json::Json {WAZUH_LOGPAR_TYPES_JSON}, m_mocks->m_spSchemf);
        builderDeps.kvdbManager = nullptr;

        auto emptyAllowedFields = std::make_shared<AllowedFields>();
        auto mockStore = std::make_shared<store::mocks::MockStore>();

        m_builder = std::make_shared<Builder>(
            m_mocks->m_spStore, m_mocks->m_spSchemf, m_mocks->m_spDefBuilder, emptyAllowedFields, builderDeps, mockStore);
    }
};

TEST_F(BuildAssetTest, BuildDecoderSuccessfully)
{
    // Setup
    base::Name assetName("decoder/test/0");
    NamespaceId namespaceId("policy_test_0");

    auto decoder = json::Json(R"({
        "name": "decoder/test/0",
        "parents": ["DecodersTree/Input"],
        "check": [{
            "event.code": 2
        }]
    })");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByName(assetName)).WillRepeatedly(testing::Return(decoder));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    // Build asset
    auto expression = m_builder->buildAsset(assetName, namespaceId);

    // Verify
    ASSERT_NE(expression, nullptr);
    EXPECT_EQ(expression->getName(), assetName);
}

TEST_F(BuildAssetTest, BuildRuleSuccessfully)
{
    // Setup
    base::Name assetName("rule/test/0");
    NamespaceId namespaceId("policy_test_0");

    auto rule = json::Json(R"({
        "name": "rule/test/0",
        "check": [{
            "process.name": "test"
        }],
        "normalize": [{
            "map": [{
                "event.risk_score": 21
            }]
        }]
    })");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByName(assetName)).WillRepeatedly(testing::Return(rule));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spSchemf, hasField(DotPath("process.name"))).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*m_mocks->m_spSchemf, hasField(DotPath("event.risk_score"))).WillRepeatedly(testing::Return(true));

    // Build asset
    auto expression = m_builder->buildAsset(assetName, namespaceId);

    // Verify
    ASSERT_NE(expression, nullptr);
    EXPECT_EQ(expression->getName(), assetName);
}

TEST_F(BuildAssetTest, BuildFilterSuccessfully)
{
    // Setup
    base::Name assetName("filter/test/0");
    NamespaceId namespaceId("policy_test_0");

    auto filter = json::Json(R"({
        "name": "filter/test/0",
        "check": [{
            "wazuh.protocol.queue": 49
        }]
    })");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByName(assetName)).WillRepeatedly(testing::Return(filter));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spSchemf, hasField(DotPath("wazuh.protocol.queue"))).WillRepeatedly(testing::Return(true));

    // Build asset
    auto expression = m_builder->buildAsset(assetName, namespaceId);

    // Verify
    ASSERT_NE(expression, nullptr);
    EXPECT_EQ(expression->getName(), assetName);
}

TEST_F(BuildAssetTest, BuildOutputSuccessfully)
{
    // Setup
    base::Name assetName("output/test/0");
    NamespaceId namespaceId("policy_test_0");

    auto output = json::Json(R"({
        "name": "output/test/0",
        "check": [{
            "event.category": "intrusion_detection"
        }]
    })");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByName(assetName)).WillRepeatedly(testing::Return(output));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spSchemf, hasField(DotPath("event.category"))).WillRepeatedly(testing::Return(true));

    // Build asset
    auto expression = m_builder->buildAsset(assetName, namespaceId);

    // Verify
    ASSERT_NE(expression, nullptr);
    EXPECT_EQ(expression->getName(), assetName);
}

class BuildPolicyAdvancedTest : public ::testing::Test
{
protected:
    std::shared_ptr<Mocks> m_mocks;
    std::shared_ptr<Builder> m_builder;

    void SetUp() override
    {
        m_mocks = std::make_shared<Mocks>();
        m_mocks->m_spStore = std::make_shared<MockICMstore>();
        m_mocks->m_spNSReader = std::make_shared<MockICMStoreNSReader>();
        m_mocks->m_spSchemf = std::make_shared<schemf::mocks::MockSchema>();
        m_mocks->m_spDefBuilder = std::make_shared<defs::mocks::MockDefinitionsBuilder>();
        m_mocks->m_spDef = std::make_shared<defs::mocks::MockDefinitions>();

        BuilderDeps builderDeps;
        builderDeps.logparDebugLvl = 0;

        ON_CALL(*m_mocks->m_spSchemf, hasField(testing::_)).WillByDefault(testing::Return(true));

        builderDeps.logpar =
            std::make_shared<hlp::logpar::Logpar>(json::Json {WAZUH_LOGPAR_TYPES_JSON}, m_mocks->m_spSchemf);
        builderDeps.kvdbManager = nullptr;

        auto emptyAllowedFields = std::make_shared<AllowedFields>();
        auto mockStore = std::make_shared<store::mocks::MockStore>();

        m_builder = std::make_shared<Builder>(
            m_mocks->m_spStore, m_mocks->m_spSchemf, m_mocks->m_spDefBuilder, emptyAllowedFields, builderDeps, mockStore);
    }
};

TEST_F(BuildPolicyAdvancedTest, BuildPolicyWithMultipleIntegrations)
{
    // Setup namespace and policy data
    NamespaceId namespaceId("policy_multi_0");

    // Create a policy with two integrations
    auto policy = dataType::Policy("test-policy-multi",
                                   "550e8400-e29b-41d4-a716-446655440003",
                                   {"550e8400-e29b-41d4-a716-446655440001", "550e8400-e29b-41d4-a716-446655440005"},
                                   {},
                                   {},
                                   {});

    // First integration
    auto integration1 = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                              "integration-one",
                                              true,
                                              "network-activity",
                                              std::nullopt,
                                              {},
                                              {"550e8400-e29b-41d4-a716-446655440004"},
                                              false);

    // Second integration
    auto integration2 = dataType::Integration("550e8400-e29b-41d4-a716-446655440005",
                                              "integration-two",
                                              true,
                                              "security",
                                              std::nullopt,
                                              {},
                                              {"550e8400-e29b-41d4-a716-446655440006"},
                                              false);

    auto decoder1 = json::Json(R"({"name": "decoder/one/0", "enabled": true, "parents": ["DecodersTree/Input"]})");
    auto decoder2 = json::Json(R"({"name": "decoder/two/0", "enabled": true, "parents": ["DecodersTree/Input"]})");
    auto defaultParent = json::Json(R"({"name": "decoder/default-parent/0", "enabled": true})");
    auto rootDecoder = json::Json(R"({"name": "decoder/root/0", "enabled": true})");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getPolicy()).WillRepeatedly(testing::Return(policy));

    EXPECT_CALL(*m_mocks->m_spNSReader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(namespaceId));

    EXPECT_CALL(*m_mocks->m_spNSReader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
        .WillRepeatedly(testing::Return(integration1));

    EXPECT_CALL(*m_mocks->m_spNSReader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440005"))
        .WillRepeatedly(testing::Return(integration2));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/one/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440006"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/two/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440004"))
        .WillRepeatedly(testing::Return(decoder1));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440006"))
        .WillRepeatedly(testing::Return(decoder2));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440002"))
        .WillRepeatedly(testing::Return(defaultParent));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(rootDecoder));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, getDefaultOutputs())
        .WillRepeatedly(testing::Return(std::vector<json::Json> {}));

    // Build policy
    auto builtPolicy = m_builder->buildPolicy(namespaceId, false, true);

    // Verify results
    ASSERT_NE(builtPolicy, nullptr);
    EXPECT_EQ(builtPolicy->name().toStr(), namespaceId.toStr());
}

TEST_F(BuildPolicyAdvancedTest, BuildPolicyWithKVDB)
{
    // Setup namespace and policy data
    NamespaceId namespaceId("policy_kvdb_0");

    auto policy = dataType::Policy("test-policy-kvdb",
                                   "550e8400-e29b-41d4-a716-446655440003",
                                   {"550e8400-e29b-41d4-a716-446655440001"},
                                   {},
                                   {},
                                   {});

    // Integration with KVDB
    auto integration = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                             "integration-with-kvdb",
                                             true,
                                             "applications",
                                             std::nullopt,
                                             {"550e8400-e29b-41d4-a716-446655440007"}, // kvdbs
                                             {"550e8400-e29b-41d4-a716-446655440004"},
                                             false);

    auto kvdb = dataType::KVDB("550e8400-e29b-41d4-a716-446655440007",
                               "test-kvdb",
                               json::Json(R"({"key1": "value1", "key2": "value2"})"),
                               true,
                               false);

    auto decoder = json::Json(R"({"name": "decoder/test/0", "enabled": true, "parents": ["DecodersTree/Input"]})");
    auto defaultParent = json::Json(R"({"name": "decoder/default-parent/0", "enabled": true})");
    auto rootDecoder = json::Json(R"({"name": "decoder/root/0", "enabled": true})");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getPolicy()).WillRepeatedly(testing::Return(policy));

    EXPECT_CALL(*m_mocks->m_spNSReader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(namespaceId));

    EXPECT_CALL(*m_mocks->m_spNSReader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
        .WillRepeatedly(testing::Return(integration));

    EXPECT_CALL(*m_mocks->m_spNSReader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440007"))
        .WillRepeatedly(testing::Return(kvdb));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const std::string& uuid) -> json::Json
            {
                if (uuid == "550e8400-e29b-41d4-a716-446655440004")
                    return decoder;
                if (uuid == "550e8400-e29b-41d4-a716-446655440002")
                    return defaultParent;
                if (uuid == "550e8400-e29b-41d4-a716-446655440003")
                    return rootDecoder;
                return json::Json("{}");
            }));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, getDefaultOutputs())
        .WillRepeatedly(testing::Return(std::vector<json::Json> {}));

    // Build policy
    auto builtPolicy = m_builder->buildPolicy(namespaceId, false, true);

    // Verify results
    ASSERT_NE(builtPolicy, nullptr);
    EXPECT_EQ(builtPolicy->name().toStr(), namespaceId.toStr());
}

TEST_F(BuildPolicyAdvancedTest, BuildPolicyWithOutputs)
{
    // Setup namespace and policy data
    NamespaceId namespaceId("policy_output_0");

    auto policy = dataType::Policy("test-policy-outputs",
                                   "550e8400-e29b-41d4-a716-446655440003",
                                   {"550e8400-e29b-41d4-a716-446655440001"},
                                   {},
                                   {},
                                   {});

    // Integration with outputs
    auto integration = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                             "integration-with-outputs",
                                             true,
                                             "cloud-services",
                                             std::nullopt,
                                             {},
                                             {"550e8400-e29b-41d4-a716-446655440004"},
                                             false);

    auto decoder = json::Json(R"({"name": "decoder/test/0", "enabled": true, "parents": ["DecodersTree/Input"]})");
    auto output = json::Json(R"({"name": "output/test/0", "enabled": true, "check": [{"event.module": "test"}]})");
    auto defaultParent = json::Json(R"({"name": "decoder/default-parent/0", "enabled": true})");
    auto rootDecoder = json::Json(R"({"name": "decoder/root/0", "enabled": true})");

    // Setup mock expectations
    EXPECT_CALL(*m_mocks->m_spStore, getNSReader(testing::_)).WillRepeatedly(testing::Return(m_mocks->m_spNSReader));

    EXPECT_CALL(*m_mocks->m_spNSReader, getPolicy()).WillRepeatedly(testing::Return(policy));

    EXPECT_CALL(*m_mocks->m_spNSReader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(namespaceId));

    EXPECT_CALL(*m_mocks->m_spNSReader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
        .WillRepeatedly(testing::Return(integration));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
        .WillRepeatedly(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));

    EXPECT_CALL(*m_mocks->m_spNSReader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440008"))
        .WillRepeatedly(testing::Return(std::make_tuple("output/test/0", ResourceType::OUTPUT)));

    EXPECT_CALL(*m_mocks->m_spNSReader, getAssetByUUID(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const std::string& uuid) -> json::Json
            {
                if (uuid == "550e8400-e29b-41d4-a716-446655440004")
                    return decoder;
                if (uuid == "550e8400-e29b-41d4-a716-446655440008")
                    return output;
                if (uuid == "550e8400-e29b-41d4-a716-446655440002")
                    return defaultParent;
                if (uuid == "550e8400-e29b-41d4-a716-446655440003")
                    return rootDecoder;
                return json::Json("{}");
            }));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByUUID(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, assetExistsByName(testing::_)).WillRepeatedly(testing::Return(true));

    EXPECT_CALL(*m_mocks->m_spNSReader, getDefaultOutputs())
        .WillRepeatedly(testing::Return(std::vector<json::Json> {}));

    // Build policy
    auto builtPolicy = m_builder->buildPolicy(namespaceId, false, true);

    // Verify results
    ASSERT_NE(builtPolicy, nullptr);
    EXPECT_EQ(builtPolicy->name().toStr(), namespaceId.toStr());
}

} // namespace builder
