#include <gtest/gtest.h>

#include <base/behaviour.hpp>

#include "definitions.hpp"

using namespace base::test;
using namespace cm::store;
using namespace builder::test;

namespace Validate
{

using SuccessExpected =
    InnerExpected<None, const std::shared_ptr<MockICMstore>&, const std::shared_ptr<MockICMStoreNSReader>&>;
using FailureExpected =
    InnerExpected<std::string, const std::shared_ptr<MockICMstore>&, const std::shared_ptr<MockICMStoreNSReader>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

// Policy validation tests
using ValidatePol = std::tuple<std::string, dataType::Policy, Expc>;

class ValidatePolicy : public BuilderTestFixture<ValidatePol>
{
};

TEST_P(ValidatePolicy, Doc)
{
    auto [namespaceId, policy, expected] = GetParam();

    auto nsId = NamespaceId(namespaceId);

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader);

        EXPECT_CALL(*m_spMocks->m_spStore, getNSReader(testing::_))
            .WillRepeatedly(testing::Return(m_spMocks->m_spNSReader));
        EXPECT_CALL(*m_spMocks->m_spNSReader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(nsId));

        auto result = m_spBuilder->softPolicyValidate(m_spMocks->m_spNSReader, policy);
        EXPECT_FALSE(result.has_value()) << "Expected success but got: " << result.value().message;
    }
    else
    {
        auto errorMsg = expected.failCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader);

        EXPECT_CALL(*m_spMocks->m_spStore, getNSReader(testing::_))
            .WillRepeatedly(testing::Return(m_spMocks->m_spNSReader));
        EXPECT_CALL(*m_spMocks->m_spNSReader, getNamespaceId()).WillRepeatedly(testing::ReturnRef(nsId));

        auto result = m_spBuilder->softPolicyValidate(m_spMocks->m_spNSReader, policy);
        ASSERT_TRUE(result.has_value()) << "Expected failure but validation succeeded";
        EXPECT_TRUE(result.value().message.find(errorMsg) != std::string::npos)
            << "Expected error containing '" << errorMsg << "' but got: " << result.value().message;
    }
}

INSTANTIATE_TEST_SUITE_P(
    Policy,
    ValidatePolicy,
    ::testing::Values(
        // Root decoder does not exist
        ValidatePol("policy_test_0",
                    dataType::Policy("test-policy",
                                     "550e8400-e29b-41d4-a716-446655440003", // root decoder UUID
                                     {"550e8400-e29b-41d4-a716-446655440001"},
                                     {},
                                     {},
                                     {}),
                   
                    FAILURE(FailureExpected::Behaviour {
                        [](const auto& store, const auto& reader)
                        {
                            EXPECT_CALL(*reader, assetExistsByUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillOnce(testing::Return(false));
                            EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillOnce(testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));
                            return "Root decoder 'decoder/root/0' does not exist";
                        }})),
        // Root decoder exists but integration UUID is invalid
        ValidatePol("policy_test_0",
                    dataType::Policy("test-policy", "550e8400-e29b-41d4-a716-446655440003",
                                     {"550e8400-e29b-41d4-a716-446655440001"}, {}, {}, {}),
                    FAILURE(FailureExpected::Behaviour {
                        [](const auto& store, const auto& reader)
                        {
                            EXPECT_CALL(*reader, assetExistsByUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillRepeatedly(testing::Return(true));
                            EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillRepeatedly(
                                    testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));
                            EXPECT_CALL(*reader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillRepeatedly(testing::Return(json::Json(R"({"name": "decoder/root/0"})")));
                            EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
                                .WillOnce(testing::Throw(std::runtime_error("Integration not found")));
                            return "Failed to resolve integration";
                        }})),
        // Valid policy with root decoder and integration
        ValidatePol("policy_test_0",
                    dataType::Policy("test-policy", "550e8400-e29b-41d4-a716-446655440003",
                                     {"550e8400-e29b-41d4-a716-446655440001"}, {}, {}, {}),
                    SUCCESS(SuccessExpected::Behaviour {
                        [](const auto& store, const auto& reader)
                        {
                            auto integration = dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                                                     "test-integration",
                                                                     true,
                                                                     "system-activity",
                                                                     std::nullopt,
                                                                     {},
                                                                     {},
                                                                     false);

                            EXPECT_CALL(*reader, assetExistsByUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillRepeatedly(testing::Return(true));
                            EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillRepeatedly(
                                    testing::Return(std::make_tuple("decoder/root/0", ResourceType::DECODER)));
                            EXPECT_CALL(*reader, getAssetByUUID("550e8400-e29b-41d4-a716-446655440003"))
                                .WillRepeatedly(testing::Return(json::Json(R"({"name": "decoder/root/0"})")));
                            EXPECT_CALL(*reader, getIntegrationByUUID("550e8400-e29b-41d4-a716-446655440001"))
                                .WillOnce(testing::Return(integration));
                            return None {};
                        }}))));

// Asset validation tests
using ValidateA = std::tuple<json::Json, bool, Expc>; // json, useNSReader, expected

class ValidateAsset : public BuilderTestFixture<ValidateA>
{
};

TEST_P(ValidateAsset, Doc)
{
    auto [assetJson, useNSReader, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader);

        if (useNSReader)
        {
            auto result = m_spBuilder->validateAsset(m_spMocks->m_spNSReader, assetJson);
            EXPECT_FALSE(result.has_value()) << "Expected success but got: " << result.value().message;
        }
        else
        {
            auto result = m_spBuilder->validateAssetShallow(assetJson);
            EXPECT_FALSE(result.has_value()) << "Expected success but got: " << result.value().message;
        }
    }
    else
    {
        auto errorMsg = expected.failCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader);

        if (useNSReader)
        {
            auto result = m_spBuilder->validateAsset(m_spMocks->m_spNSReader, assetJson);
            ASSERT_TRUE(result.has_value()) << "Expected failure but validation succeeded";
            EXPECT_TRUE(result.value().message.find(errorMsg) != std::string::npos)
                << "Expected error containing '" << errorMsg << "' but got: " << result.value().message;
        }
        else
        {
            auto result = m_spBuilder->validateAssetShallow(assetJson);
            ASSERT_TRUE(result.has_value()) << "Expected failure but validation succeeded";
            EXPECT_TRUE(result.value().message.find(errorMsg) != std::string::npos)
                << "Expected error containing '" << errorMsg << "' but got: " << result.value().message;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(Asset,
                         ValidateAsset,
                         ::testing::Values(
                             // Empty object
                             ValidateA(json::Json(R"({})"),
                                       false,
                                       FAILURE(FailureExpected::Behaviour {[](const auto&, const auto&)
                                                                           {
                                                                               return "Document is empty";
                                                                           }})),
                             // Missing name
                             ValidateA(json::Json(R"({"check": []})"),
                                       false,
                                       FAILURE(FailureExpected::Behaviour {[](const auto&, const auto&)
                                                                           {
                                                                               return "name";
                                                                           }})),
                             // Invalid name format
                             ValidateA(json::Json(R"({"name": "decoder//"})"),
                                       false,
                                       FAILURE(FailureExpected::Behaviour {[](const auto&, const auto&)
                                                                           {
                                                                               return "Name cannot have empty parts";
                                                                           }})),
                             // Valid decoder (shallow)
                             ValidateA(json::Json(R"({
                      "name": "decoder/test/0",
                      "parents": ["decoder/Input"],
                      "check": [{"event.code": 2}]
                  })"),
                                       false,
                                       SUCCESS(SuccessExpected::Behaviour {[](const auto&, const auto&)
                                                                           {
                                                                               return None {};
                                                                           }})),
                             // Decoder with missing parent (deep validation)
                             ValidateA(json::Json(R"({
                      "name": "decoder/test/0",
                      "parents": ["decoder/missing/0"],
                      "check": [{"event.code": 2}]
                  })"),
                                       true,
                                       FAILURE(FailureExpected::Behaviour {
                                           [](const auto& store, const auto& reader)
                                           {
                                               EXPECT_CALL(*reader, assetExistsByName(base::Name("decoder/missing/0")))
                                                   .WillOnce(testing::Return(false));
                                               return "Parent 'decoder/missing/0' referenced by asset";
                                           }})),
                             // Valid decoder with existing parent (deep validation)
                             ValidateA(json::Json(R"({
                      "name": "decoder/test/0",
                      "parents": ["decoder/Input"],
                      "check": [{"event.code": 2}]
                  })"),
                                       true,
                                       SUCCESS(SuccessExpected::Behaviour {
                                           [](const auto& store, const auto& reader)
                                           {
                                               EXPECT_CALL(*reader, assetExistsByName(base::Name("decoder/Input")))
                                                   .WillOnce(testing::Return(true));
                                               return None {};
                                           }}))));

// Integration validation tests
using ValidateI = std::tuple<dataType::Integration, Expc>;

class ValidateIntegration : public BuilderTestFixture<ValidateI>
{
};

TEST_P(ValidateIntegration, Doc)
{
    auto [integration, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader);

        auto result = m_spBuilder->softIntegrationValidate(m_spMocks->m_spNSReader, integration);
        EXPECT_FALSE(result.has_value()) << "Expected success but got: " << result.value().message;
    }
    else
    {
        auto errorMsg = expected.failCase()(m_spMocks->m_spStore, m_spMocks->m_spNSReader);

        auto result = m_spBuilder->softIntegrationValidate(m_spMocks->m_spNSReader, integration);
        ASSERT_TRUE(result.has_value()) << "Expected failure but validation succeeded";
        EXPECT_TRUE(result.value().message.find(errorMsg) != std::string::npos)
            << "Expected error containing '" << errorMsg << "' but got: " << result.value().message;
    }
}

INSTANTIATE_TEST_SUITE_P(
    Integration,
    ValidateIntegration,
    ::testing::Values(
        // Disabled integration (should pass)
        ValidateI(dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                        "disabled-integration",
                                        false, // disabled
                                        "system-activity",
                                        std::nullopt,
                                        {},
                                        {},

                                        false),
                  SUCCESS()),
        // Missing decoder
        ValidateI(dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                        "test-integration",
                                        true,
                                        "system-activity",
                                        std::nullopt,
                                        {},
                                        {"550e8400-e29b-41d4-a716-446655440004"}, // decoder UUID
                                        false),
                  FAILURE(FailureExpected::Behaviour {
                      [](const auto& store, const auto& reader)
                      {
                          EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));
                          EXPECT_CALL(*reader, assetExistsByUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(false));
                          return "does not exist";
                      }})),
        // Integration with decoder that references undeclared KVDB
        // softIntegrationValidate no longer validates KVDB references (validation happens during policy build)
        ValidateI(dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                        "test-integration",
                                        true,
                                        "applications",
                                        std::nullopt,
                                        {}, // no KVDBs declared
                                        {"550e8400-e29b-41d4-a716-446655440004"},

                                        false),
                  SUCCESS(SuccessExpected::Behaviour {
                      [](const auto& store, const auto& reader)
                      {
                          EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));
                          EXPECT_CALL(*reader, assetExistsByUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(true));

                          return None {};
                      }})),
        // KVDB disabled - softIntegrationValidate only checks KVDB existence, not enabled status
        ValidateI(dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                        "test-integration",
                                        true,
                                        "applications",
                                        std::nullopt,
                                        {"550e8400-e29b-41d4-a716-446655440007"}, // KVDB UUID
                                        {"550e8400-e29b-41d4-a716-446655440004"},
                                        false),
                  SUCCESS(SuccessExpected::Behaviour {
                      [](const auto& store, const auto& reader)
                      {
                          auto kvdb = dataType::KVDB("550e8400-e29b-41d4-a716-446655440007",
                                                     "testdb",
                                                     json::Json(R"({})"),
                                                     false, // disabled
                                                     false);

                          EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440007"))
                              .WillOnce(testing::Return(std::make_tuple("testdb", ResourceType::KVDB)));
                          EXPECT_CALL(*reader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440007"))
                              .WillOnce(testing::Return(kvdb));
                          EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));
                          EXPECT_CALL(*reader, assetExistsByUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(true));

                          return None {};
                      }})),
        // Valid integration with KVDB
        ValidateI(dataType::Integration("550e8400-e29b-41d4-a716-446655440001",
                                        "test-integration",
                                        true,
                                        "applications",
                                        std::nullopt,
                                        {"550e8400-e29b-41d4-a716-446655440007"},
                                        {"550e8400-e29b-41d4-a716-446655440004"},
                                        false),
                  SUCCESS(SuccessExpected::Behaviour {
                      [](const auto& store, const auto& reader)
                      {
                          auto kvdb = dataType::KVDB("550e8400-e29b-41d4-a716-446655440007",
                                                     "testdb",
                                                     json::Json(R"({})"),
                                                     true, // enabled
                                                     false);

                          EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440007"))
                              .WillOnce(testing::Return(std::make_tuple("testdb", ResourceType::KVDB)));
                          EXPECT_CALL(*reader, getKVDBByUUID("550e8400-e29b-41d4-a716-446655440007"))
                              .WillOnce(testing::Return(kvdb));
                          EXPECT_CALL(*reader, resolveNameFromUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(std::make_tuple("decoder/test/0", ResourceType::DECODER)));
                          EXPECT_CALL(*reader, assetExistsByUUID("550e8400-e29b-41d4-a716-446655440004"))
                              .WillOnce(testing::Return(true));

                          return None {};
                      }}))));

} // namespace Validate
