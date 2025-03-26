#include <gtest/gtest.h>

#include "definitions.hpp"

using namespace base::test;
using namespace store::mocks;
using namespace schemf::mocks;
using namespace defs::mocks;
using namespace builder::test;

namespace Validate
{

using SuccessExpected = InnerExpected<None,
                                      const std::shared_ptr<MockStore>&,
                                      const std::shared_ptr<MockDefinitionsBuilder>&,
                                      const std::shared_ptr<defs::mocks::MockDefinitions>&,
                                      const std::shared_ptr<schemf::mocks::MockSchema>&>;
using FailureExpected = InnerExpected<const std::string,
                                      const std::shared_ptr<MockStore>&,
                                      const std::shared_ptr<MockDefinitionsBuilder>&,
                                      const std::shared_ptr<defs::mocks::MockDefinitions>&,
                                      const std::shared_ptr<schemf::mocks::MockSchema>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();
using Validate = std::tuple<json::Json, Expc>;

class ValidatePolicy : public BuilderTestFixture<Validate>
{
};

TEST_P(ValidatePolicy, Doc)
{
    auto [policy, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef, m_spMocks->m_spSchemf);
        m_spBuilder->validatePolicy(policy);
    }
    else
    {
        auto response = expected.failCase()(
            m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef, m_spMocks->m_spSchemf);
        EXPECT_STREQ(m_spBuilder->validatePolicy(policy).value().message.c_str(), response.c_str());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Policy,
    ValidatePolicy,
    ::testing::Values(
        // start
        Validate(json::Json {DEFECTIVE_POLICY_NAME_JSON},
                 FAILURE([](const std::shared_ptr<MockStore>& store,
                            const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                            const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                            const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                         { return "Could not find policy name string attribute at '/name'"; })),
        Validate(json::Json {DEFECTIVE_POLICY_FORMAT_NAME_JSON},
                 FAILURE([](const std::shared_ptr<MockStore>& store,
                            const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                            const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                            const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                         { return "Name cannot be empty"; })),
        Validate(json::Json {DEFECTIVE_POLICY_HASH_JSON},
                 FAILURE([](const std::shared_ptr<MockStore>& store,
                            const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                            const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                            const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                         { return "Could not find policy hash string attribute at '/hash'"; })),
        Validate(json::Json {DEFECTIVE_POLICY_EMPTY_HASH_JSON},
                 FAILURE([](const std::shared_ptr<MockStore>& store,
                            const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                            const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                            const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                         { return "Policy hash string attribute at '/hash' is empty"; })),
        Validate(json::Json {DEFECTIVE_PARENT_POLICY_EMPTY_NAME_JSON},
                 FAILURE([](const std::shared_ptr<MockStore>& store,
                            const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                            const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                            const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                         { return "Invalid default parent name '': Name cannot be empty"; })),
        Validate(json::Json {DEFECTIVE_PARENT_POLICY_NOT_STRING_NAME_JSON},
                 FAILURE([](const std::shared_ptr<MockStore>& store,
                            const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                            const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                            const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                         { return "Default parent asset in namespace 'system' is not a string"; })),
        Validate(json::Json {DEFECTIVE_ASSET_POLICY_NOT_STRING_NAME_JSON},
                 FAILURE([](const std::shared_ptr<MockStore>& store,
                            const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                            const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                            const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                         { return "Invalid not string entry in '/assets' array"; })),
        Validate(json::Json {POLICY_JSON},
                 FAILURE(
                     [](const std::shared_ptr<MockStore>& store,
                        const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                        const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                        const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                     {
                         EXPECT_CALL(*store, getNamespace(testing::_)).WillOnce(testing::Return("wazuh"));
                         EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(base::Error {"ERROR"}));
                         return "Could not read document for integration 'integration/test/0'";
                     })),
        Validate(json::Json {POLICY_JSON},
                 SUCCESS(
                     [](const std::shared_ptr<MockStore>& store,
                        const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                        const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                        const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                     {
                         EXPECT_CALL(*store, getNamespace(testing::_))
                             .WillRepeatedly(testing::Invoke(
                                 [&](const base::Name& name)
                                 {
                                     if (name == "integration/test/0")
                                     {
                                         return "system";
                                     }
                                     else if (name == "decoder/test/0")
                                     {
                                         return "system";
                                     }
                                     else if (name == "decoder/parent-test/0")
                                     {
                                         return "system";
                                     }
                                     return "";
                                 }));
                         EXPECT_CALL(*store, readDoc(testing::_))
                             .WillRepeatedly(testing::Invoke(
                                 [&](const base::Name& name)
                                 {
                                     if (name == "integration/test/0")
                                     {
                                         return json::Json {INTEGRATION_JSON};
                                     }
                                     else if (name == "decoder/parent-test/0")
                                     {
                                         return json::Json {DECODER_PARENT_JSON};
                                     }
                                     else if (name == "decoder/test/0")
                                     {
                                         return json::Json {DECODER_JSON};
                                     }
                                     return json::Json {};
                                 }));
                         EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                         EXPECT_CALL(*schemf, validate(testing::_, testing::_))
                             .WillRepeatedly(testing::Return(schemf::ValidationResult()));
                         return None {};
                     }))
        // end
        ));

using SuccessValidateAssetExpected = InnerExpected<None,
                                                   const std::shared_ptr<MockSchema>&,
                                                   const std::shared_ptr<MockDefinitionsBuilder>&,
                                                   const std::shared_ptr<MockDefinitions>&>;
using FailureValidateAssetExpected = InnerExpected<const std::string,
                                                   const std::shared_ptr<MockSchema>&,
                                                   const std::shared_ptr<MockDefinitionsBuilder>&,
                                                   const std::shared_ptr<MockDefinitions>&>;
using ExpcAsset = Expected<SuccessValidateAssetExpected, FailureValidateAssetExpected>;
auto SUCCESS_ASSET = ExpcAsset::success();
auto FAILURE_ASSET = ExpcAsset::failure();
using ValidateA = std::tuple<json::Json, ExpcAsset>;

class ValidateAsset : public BuilderTestFixture<ValidateA>
{
};

TEST_P(ValidateAsset, Doc)
{
    auto [asset, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spSchemf, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef);
        m_spBuilder->validateAsset(asset);
    }
    else
    {
        auto response = expected.failCase()(m_spMocks->m_spSchemf, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef);
        EXPECT_STREQ(m_spBuilder->validateAsset(asset).value().message.c_str(), response.c_str());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Asset,
    ValidateAsset,
    ::testing::Values(
        // start
        ValidateA(json::Json {R"([])"},
                  FAILURE_ASSET([](const std::shared_ptr<MockSchema>& schema,
                                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                { return "Document is not an object"; })),
        ValidateA(json::Json {R"({})"},
                  FAILURE_ASSET([](const std::shared_ptr<MockSchema>& schema,
                                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                { return "Document is empty"; })),
        ValidateA(json::Json {DECODER_KEY_DEFECTIVE_JSON},
                  FAILURE_ASSET([](const std::shared_ptr<MockSchema>& schema,
                                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                { return "Expected 'name' key in asset document but got 'id'"; })),
        ValidateA(json::Json {DECODER_NOT_STRING_NAME_JSON},
                  FAILURE_ASSET([](const std::shared_ptr<MockSchema>& schema,
                                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                { return "Expected 'name' to be a 'string' but got 'number'"; })),
        ValidateA(json::Json {DECODER_INVALID_FORMAT_NAME_JSON},
                  FAILURE_ASSET([](const std::shared_ptr<MockSchema>& schema,
                                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                { return "Invalid name 'decoder//': Name cannot have empty parts"; })),
        ValidateA(json::Json {DECODER_INVALID_FORMAT_PARENT_JSON},
                  FAILURE_ASSET([](const std::shared_ptr<MockSchema>& schema,
                                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                { return "Expected 'parents' to be an 'array' but got 'object'"; })),
        ValidateA(json::Json {DECODER_INVALID_VALUE_PARENT_JSON},
                  FAILURE_ASSET([](const std::shared_ptr<MockSchema>& schema,
                                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                { return "Found non-string value 'number' in 'parents'"; })),
        ValidateA(json::Json {DECODER_EMPTY_STAGE_PARSE_JSON},
                  FAILURE_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return "Stage 'parse' expects a non-empty array but got an empty array";
                      })),
        ValidateA(json::Json {DECODER_STAGE_PARSE_FIELD_NOT_FOUND_JSON},
                  SUCCESS_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*schema, hasField(DotPath("event.notExist"))).WillOnce(testing::Return(false));
                          EXPECT_CALL(*def, replace(testing::_))
                              .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return None {};
                      })),
        // TODO: This should warn that the parse field does not exist
        ValidateA(json::Json {DECODER_STAGE_PARSE_NOT_FOUND_JSON},
                  FAILURE_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*schema, hasField(testing::_)).WillOnce(testing::Return(true));
                          EXPECT_CALL(*def, replace(testing::_))
                              .WillOnce(testing::Invoke([](auto expr) { return std::string(expr); }));
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return "An error occurred while parsing a log: Parser type 'text' not found";
                      })),
        ValidateA(json::Json {DECODER_STAGE_PARSE_WITHOUT_SEPARATOR_JSON},
                  FAILURE_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return "Stage parse: needs the character '|' to indicate the field";
                      })),
        ValidateA(json::Json {DECODER_STAGE_NORMALIZE_WRONG_MAPPING},
                  FAILURE_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*schema, validate(testing::_, testing::_))
                              .WillOnce(testing::Return(base::Error {"event.code is of type text"}));
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return "In stage 'normalize' builder for block 'map' failed with error: Failed to build "
                                 "operation 'event.code: map(2)': event.code is of type text";
                      })),
        ValidateA(json::Json {DECODER_STAGE_NORMALIZE_WRONG_PARSE_WITHOUT_SEPARATOR},
                  FAILURE_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*schema, validate(testing::_, testing::_))
                              .WillRepeatedly(testing::Return(schemf::ValidationResult()));
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return "Stage parse: needs the character '|' to indicate the field";
                      })),
        ValidateA(json::Json {DECODER_STAGE_NORMALIZE_WRONG_PARSE_WITHOUT_FIELD},
                  SUCCESS_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*schema, validate(testing::_, testing::_))
                              .WillRepeatedly(testing::Return(schemf::ValidationResult()));
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return None {};
                      })),
        ValidateA(json::Json {DECODER_JSON},
                  SUCCESS_ASSET(
                      [](const std::shared_ptr<MockSchema>& schema,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return None {};
                      }))
        // end
        ));

using SuccessValidateIntegrationExpected = InnerExpected<None,
                                                         const std::shared_ptr<MockStore>&,
                                                         const std::shared_ptr<MockDefinitionsBuilder>&,
                                                         const std::shared_ptr<defs::mocks::MockDefinitions>&>;
using FailureValidateIntegrationExpected = InnerExpected<const std::string,
                                                         const std::shared_ptr<MockStore>&,
                                                         const std::shared_ptr<MockDefinitionsBuilder>&,
                                                         const std::shared_ptr<defs::mocks::MockDefinitions>&>;
using ExpcIntegration = Expected<SuccessValidateIntegrationExpected, FailureValidateIntegrationExpected>;
auto SUCCESS_INTEGRATION = ExpcIntegration::success();
auto FAILURE_INTEGRATION = ExpcIntegration::failure();
using ValidateI = std::tuple<json::Json, std::string, ExpcIntegration>;

class ValidateIntegration : public BuilderTestFixture<ValidateI>
{
};

TEST_P(ValidateIntegration, Doc)
{
    auto [integration, namespaceId, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef);
        m_spBuilder->validateIntegration(integration, namespaceId);
    }
    else
    {
        auto response = expected.failCase()(m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef);
        EXPECT_STREQ(m_spBuilder->validateIntegration(integration, namespaceId).value().message.c_str(),
                     response.c_str());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Integration,
    ValidateIntegration,
    ::testing::Values(
        // start
        ValidateI(json::Json {INTEGRATION_KEY_DEFECTIVE_JSON},
                  "",
                  FAILURE_INTEGRATION([](const std::shared_ptr<MockStore>& store,
                                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                                      { return "Integration name not found"; })),
        ValidateI(json::Json {INTEGRATION_INVALID_FORMAT_JSON},
                  "wazuh",
                  FAILURE_INTEGRATION(
                      [](const std::shared_ptr<MockStore>& store,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          return "Invalid not string entry in '/decoders' array for integration 'integration/test/0'";
                      })),
        ValidateI(json::Json {INTEGRATION_INVALID_FORMAT_NAME_JSON},
                  "wazuh",
                  FAILURE_INTEGRATION(
                      [](const std::shared_ptr<MockStore>& store,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          return "Invalid asset name 'decoder//' in integration 'integration/test/0': Name cannot have "
                                 "empty parts";
                      })),
        ValidateI(json::Json {INTEGRATION_INVALID_ASSET_TYPE_JSON},
                  "wazuh",
                  FAILURE_INTEGRATION(
                      [](const std::shared_ptr<MockStore>& store,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          return "Asset 'decoder-non-exist/test/0' in integration 'integration/test/0' is not of type "
                                 "'decoder'";
                      })),
        ValidateI(json::Json {INTEGRATION_JSON},
                  "wazuh",
                  FAILURE_INTEGRATION(
                      [](const std::shared_ptr<MockStore>& store,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*store, getNamespace(testing::_)).WillOnce(testing::Return(std::nullopt));
                          return "Could not find namespace for asset 'decoder/test/0'";
                      })),
        ValidateI(
            json::Json {INTEGRATION_JSON},
            "wazuh",
            FAILURE_INTEGRATION(
                [](const std::shared_ptr<MockStore>& store,
                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                   const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                {
                    EXPECT_CALL(*store, getNamespace(testing::_)).WillOnce(testing::Return("system"));
                    return "Asset 'decoder/test/0' in integration 'integration/test/0' is not in the same namespace";
                })),
        ValidateI(json::Json {INTEGRATION_JSON},
                  "wazuh",
                  FAILURE_INTEGRATION(
                      [](const std::shared_ptr<MockStore>& store,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*store, getNamespace(testing::_))
                              .WillRepeatedly(testing::Invoke(
                                  [&](const base::Name& name)
                                  {
                                      if (name == "decoder/test/0")
                                      {
                                          return "wazuh";
                                      }
                                      else if (name == "decoder/parent-test/0")
                                      {
                                          return "system";
                                      }
                                      return "";
                                  }));
                          return "Asset 'decoder/parent-test/0' in integration 'integration/test/0' is not in the same "
                                 "namespace";
                      })),
        ValidateI(json::Json {INTEGRATION_JSON},
                  "wazuh",
                  SUCCESS_INTEGRATION(
                      [](const std::shared_ptr<MockStore>& store,
                         const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                         const std::shared_ptr<defs::mocks::MockDefinitions>& def)
                      {
                          EXPECT_CALL(*store, getNamespace(testing::_))
                              .WillRepeatedly(testing::Invoke(
                                  [&](const base::Name& name)
                                  {
                                      if (name == "decoder/test/0")
                                      {
                                          return "wazuh";
                                      }
                                      else if (name == "decoder/parent-test/0")
                                      {
                                          return "wazuh";
                                      }
                                      return "";
                                  }));
                          EXPECT_CALL(*store, readDoc(testing::_))
                              .WillRepeatedly(testing::Invoke(
                                  [&](const base::Name& name)
                                  {
                                      if (name == "decoder/parent-test/0")
                                      {
                                          return json::Json {DECODER_PARENT_WITHOUT_CHECK_JSON};
                                      }
                                      else if (name == "decoder/test/0")
                                      {
                                          return json::Json {DECODER_WITH_SIMPLE_PARENT_JSON};
                                      }
                                      return json::Json {};
                                  }));
                          EXPECT_CALL(*defBuild, build(testing::_)).WillRepeatedly(testing::Return(def));
                          return None {};
                      }))
        // end
        ));

} // namespace Validate
