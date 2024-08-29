#include <gtest/gtest.h>

#include "../expressionCmp.hpp"
#include "definitions.hpp"
#include <base/baseTypes.hpp>

using namespace builder::test;

namespace
{
/**
 * @brief User for build the params of the handler in a easy way
 *
 */
struct JParam
{

    std::optional<std::string> m_name;
    std::optional<std::string> m_hash;
    std::optional<std::vector<std::string>> m_assets;

    JParam& name(const std::string& name)
    {
        m_name = name;
        return *this;
    }

    JParam& hash(const std::string& hash)
    {
        m_hash = hash;
        return *this;
    }

    JParam& assets(const std::vector<std::string>& assets)
    {
        m_assets = assets;
        return *this;
    }

    // cast to json
    operator json::Json() const
    {
        json::Json j;
        if (m_name)
        {
            j.setString(m_name.value(), "/name");
        }
        if (m_hash)
        {
            j.setString(m_hash.value(), "/hash");
        }
        if (m_assets)
        {
            j.setArray("/assets");
            for (const auto& ns : m_assets.value())
            {
                j.appendString(ns, "/assets");
            }
        }
        return j;
    }

    // cast to string
    operator std::string() const { return json::Json(*this).str(); }
};

} // namespace

namespace builder
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
using Build = std::tuple<JParam, Expc>;

class BuildPolicy : public BuilderTestFixture<Build>
{
};

TEST_P(BuildPolicy, Doc)
{
    auto [policy, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef, m_spMocks->m_spSchemf);

        auto policyExpected = m_spBuilder->buildPolicy("policy/test/0");
        EXPECT_STREQ(policyExpected->name().toStr().c_str(),
                     static_cast<json::Json>(policy).getString("/name").value().c_str());
        EXPECT_STREQ(policyExpected->hash().c_str(),
                     static_cast<json::Json>(policy).getString("/hash").value().c_str());
        auto assets = static_cast<json::Json>(policy).getArray("/assets").value();
        EXPECT_TRUE(std::equal(assets.begin(),
                               assets.end(),
                               policyExpected->assets().begin(),
                               [](const json::Json& jsonName, const base::Name& baseName)
                               { return jsonName.getString().value() == baseName.toStr(); }));

        auto expectedExpression = base::Chain::create(
            "policy/test/0",
            {base::Or::create(
                "decoder/Input",
                {base::Implication::create(
                    "decoder/parent-test/0/Node",
                    base::And::create("decoder/parent-test/0",
                                      {base::And::create("condition",
                                                         {base::And::create("stage.check",
                                                                            {base::Term<base::EngineOp>::create(
                                                                                "event.code: filter(2)", {})}),
                                                          base::Term<base::EngineOp>::create("AcceptAll", {})})}),
                    base::Or::create("decoder/parent-test/0/Children",
                                     {base::And::create("decoder/test/0",
                                                        {base::And::create("condition",
                                                                           {base::Term<base::EngineOp>::create(
                                                                               "AcceptAll", {})})})}))})});
        assertEqualExpr(expectedExpression, policyExpected->expression());
    }
    else
    {
        auto response = expected.failCase()(
            m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef, m_spMocks->m_spSchemf);

        ASSERT_THROW(
            try { m_spBuilder->buildPolicy("policy/test/0"); } catch (const std::exception& e) {
                ASSERT_STREQ(e.what(), response.c_str());
                throw;
            },
            std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Policy,
    BuildPolicy,
    ::testing::Values(
        // start
        Build(JParam(),
              FAILURE(
                  [](const std::shared_ptr<MockStore>& store,
                     const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                     const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                     const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                  {
                      EXPECT_CALL(*store, readInternalDoc(testing::_))
                          .WillOnce(testing::Return(base::Error {"Document not exist"}));
                      return "Document not exist";
                  })),
        Build(JParam(),
              FAILURE(
                  [](const std::shared_ptr<MockStore>& store,
                     const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                     const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                     const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                  {
                      EXPECT_CALL(*store, readInternalDoc(testing::_))
                          .WillOnce(testing::Return(json::Json {POLICY_JSON}));
                      EXPECT_CALL(*store, getNamespace(testing::_)).WillOnce(testing::Return("wazuh"));
                      EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(base::Error {"ERROR"}));
                      return "Could not read document for integration 'integration/test/0'";
                  })),
        Build(JParam(),
              FAILURE(
                  [](const std::shared_ptr<MockStore>& store,
                     const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                     const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                     const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                  {
                      EXPECT_CALL(*store, readInternalDoc(testing::_))
                          .WillOnce(testing::Return(json::Json {POLICY_JSON}));
                      EXPECT_CALL(*store, getNamespace(testing::_))
                          .WillRepeatedly(testing::Invoke(
                              [&](const base::Name& name)
                              {
                                  if (name == "decoder/test/0")
                                  {
                                      return "system";
                                  }
                                  else if (name == "integration/test/0")
                                  {
                                      return "wazuh";
                                  }
                                  return "";
                              }));
                      EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(json::Json {INTEGRATION_JSON}));
                      return "Asset 'decoder/test/0' in integration 'integration/test/0' is not in the same namespace";
                  })),
        Build(JParam(),
              FAILURE(
                  [](const std::shared_ptr<MockStore>& store,
                     const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                     const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                     const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                  {
                      EXPECT_CALL(*store, readInternalDoc(testing::_))
                          .WillOnce(testing::Return(json::Json {POLICY_JSON}));
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
                                      return "wazuh";
                                  }
                                  return "";
                              }));
                      EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(json::Json {INTEGRATION_JSON}));
                      return "Asset 'decoder/parent-test/0' in integration 'integration/test/0' is not in the same "
                             "namespace";
                  })),
        Build(JParam(),
              FAILURE(
                  [](const std::shared_ptr<MockStore>& store,
                     const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                     const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                     const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                  {
                      EXPECT_CALL(*store, readInternalDoc(testing::_))
                          .WillOnce(testing::Return(json::Json {POLICY_JSON}));
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
                          .WillOnce(testing::Return(base::Error {"'event.code' not is a long"}));
                      return "Failed to build operation 'event.code: filter(2)': 'event.code' not is a long";
                  })),
        Build(JParam()
                  .name("policy/test/0")
                  .hash("11464515449720324140")
                  .assets({"decoder/parent-test/0", "decoder/test/0"}),
              SUCCESS(
                  [](const std::shared_ptr<MockStore>& store,
                     const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                     const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                     const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                  {
                      EXPECT_CALL(*store, readInternalDoc(testing::_))
                          .WillOnce(testing::Return(json::Json {POLICY_JSON}));
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

using BuildA = std::tuple<base::Expression, Expc>;
class BuildAsset : public BuilderTestFixture<BuildA>
{
};

TEST_P(BuildAsset, Doc)
{
    auto [expectedExpression, expected] = GetParam();

    if (expected)
    {
        expected.succCase()(m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef, m_spMocks->m_spSchemf);
        auto expression = m_spBuilder->buildAsset("decoder/test/0");
        assertEqualExpr(expectedExpression, expression);
    }
    else
    {
        auto response = expected.failCase()(
            m_spMocks->m_spStore, m_spMocks->m_spDefBuilder, m_spMocks->m_spDef, m_spMocks->m_spSchemf);

        ASSERT_THROW(
            try { m_spBuilder->buildAsset("decoder/test/0"); } catch (const std::exception& e) {
                EXPECT_STREQ(e.what(), response.c_str());
                throw;
            },
            std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Asset,
    BuildAsset,
    ::testing::Values(
        // start
        BuildA(
            nullptr,
            FAILURE(
                [](const std::shared_ptr<MockStore>& store,
                   const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                   const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                   const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                {
                    EXPECT_CALL(*store, readDoc(testing::_))
                        .WillOnce(testing::Return(base::Error {"Document not exist"}));
                    return "Engine utils: 'decoder/test/0' could not be obtained from the store: Document not exist.";
                })),
        BuildA(nullptr,
               FAILURE(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(json::Json {"{}"}));
                       return "Document is empty";
                   })),
        BuildA(nullptr,
               FAILURE(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(json::Json {"[]"}));
                       return "Document is not an object";
                   })),
        BuildA(nullptr,
               FAILURE(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_))
                           .WillOnce(testing::Return(json::Json {DECODER_KEY_DEFECTIVE_JSON}));
                       return "Expected 'name' key in asset document but got 'id'";
                   })),
        BuildA(nullptr,
               FAILURE(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_))
                           .WillOnce(testing::Return(json::Json {DECODER_STAGE_NOT_FOUND_JSON}));
                       return "Could not find builder for stage 'check_not_found'";
                   })),
        BuildA(nullptr,
               FAILURE(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_))
                           .WillOnce(testing::Return(json::Json {DECODER_MAP_ON_CHECK_JSON}));
                       return "Operation builder 'map' is not a filter builder";
                   })),
        BuildA(nullptr,
               FAILURE(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_))
                           .WillOnce(testing::Return(json::Json {DECODER_FILTER_ON_MAP_JSON}));
                       return "In stage 'normalize' builder for block 'map' failed with error: Operation builder "
                              "'filter' is not a map/transform builder";
                   })),
        BuildA(base::And::create("decoder/test/0",
                                 {base::And::create("condition",
                                                    {base::Term<base::EngineOp>::create("AcceptAll", {})})}),
               SUCCESS(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(json::Json {DECODER_JSON}));
                       EXPECT_CALL(*defBuild, build(testing::_)).WillOnce(testing::Return(def));
                       return None {};
                   })),
        BuildA(base::And::create("filter/test/0",
                                 {base::And::create("condition",
                                                    {base::And::create("stage.check",
                                                                       {base::Term<base::EngineOp>::create(
                                                                           "wazuh.queue: filter(49)", {})}),
                                                     base::Term<base::EngineOp>::create("AcceptAll", {})})}),
               SUCCESS(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(json::Json {FILTER_JSON}));
                       EXPECT_CALL(*defBuild, build(testing::_)).WillOnce(testing::Return(def));
                       EXPECT_CALL(*schemf, validate(testing::_, testing::_))
                           .WillRepeatedly(testing::Return(schemf::ValidationResult()));
                       return None {};
                   })),
        BuildA(base::Implication::create(
                   "rule/test/0",
                   base::And::create(
                       "condition",
                       {base::And::create("stage.check",
                                          {base::Term<base::EngineOp>::create("process.name: filter(\"test\")", {})}),
                        base::Term<base::EngineOp>::create("AcceptAll", {})}),
                   base::And::create(
                       "stages",
                       {base::Chain::create(
                            "normalize",
                            {base::And::create("subblock",
                                               {base::Chain::create("stage.map",
                                                                    {base::Term<base::EngineOp>::create(
                                                                        "event.risk_score: map(21)", {})})})}),
                        base::Term<base::EngineOp>::create("DeleteVariables", {})})),
               SUCCESS(
                   [](const std::shared_ptr<MockStore>& store,
                      const std::shared_ptr<MockDefinitionsBuilder>& defBuild,
                      const std::shared_ptr<defs::mocks::MockDefinitions>& def,
                      const std::shared_ptr<schemf::mocks::MockSchema>& schemf)
                   {
                       EXPECT_CALL(*store, readDoc(testing::_)).WillOnce(testing::Return(json::Json {RULE_JSON}));
                       EXPECT_CALL(*defBuild, build(testing::_)).WillOnce(testing::Return(def));
                       EXPECT_CALL(*schemf, validate(testing::_, testing::_))
                           .WillRepeatedly(testing::Return(schemf::ValidationResult()));
                       return None {};
                   }))
        // end
        ));

} // namespace builder
