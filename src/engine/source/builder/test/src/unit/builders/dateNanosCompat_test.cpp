// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>
#include <base/json.hpp>
#include <builder/builder.hpp>
#include <schemf/schema.hpp>

#include "builders/baseHelper.hpp"
#include "builders/buildCtx.hpp"
#include "register.hpp"
#include "registry.hpp"

#include <builder/mockAllowedFields.hpp>
#include <defs/mockDefinitions.hpp>

/*
 * DATE <-> DATE_NANOS schema compatibility exercised through the production build path:
 *  - a real schemf::Schema (the production IValidator, with its real compatibility matrix),
 *  - the production helper registry (builder::detail::registerOpBuilders, as builder::Builder does),
 *  - a real builders::BuildCtx,
 *  - builder::builders::baseHelperBuilder(const json::Json&, buildCtx, HelperType::MAP), the function the `map`
 *    stage (builders/stage/map.cpp) calls for every `field: expression` entry; it parses the expression, resolves
 *    the helper in the registry, validates it against the schema (buildType) and adds the runtime validation
 *    wrapper (runType) when the schema says so.
 * Only the allowed-fields and definitions dependencies are mocked (always allowed, no definitions).
 */

namespace
{
using namespace builder::builders;
using testing::_;
using testing::NiceMock;
using testing::Return;

class DateNanosCompatTest : public ::testing::Test
{
protected:
    std::shared_ptr<schemf::Schema> m_schema;
    std::shared_ptr<RegistryType> m_registry;
    std::shared_ptr<NiceMock<defs::mocks::MockDefinitions>> m_definitions;
    std::shared_ptr<NiceMock<builder::mocks::MockAllowedFields>> m_allowedFields;
    std::shared_ptr<BuildCtx> m_buildCtx;

    void SetUp() override
    {
        // Real schema
        m_schema = std::make_shared<schemf::Schema>();
        m_schema->addField("@timestamp", schemf::Field::Parameters {.type = schemf::Type::DATE});
        m_schema->addField("event.received", schemf::Field::Parameters {.type = schemf::Type::DATE_NANOS});
        m_schema->addField("msg", schemf::Field::Parameters {.type = schemf::Type::KEYWORD});
        m_schema->addField("event.sequence", schemf::Field::Parameters {.type = schemf::Type::LONG});

        // Production helper registry (same calls as builder::Builder's constructor)
        m_registry = RegistryType::create<builder::Registry>();
        builder::detail::registerOpBuilders<RegistryType>(m_registry, builder::BuilderDeps {});

        m_definitions = std::make_shared<NiceMock<defs::mocks::MockDefinitions>>();
        ON_CALL(*m_definitions, contains(_)).WillByDefault(Return(false));

        m_allowedFields = std::make_shared<NiceMock<builder::mocks::MockAllowedFields>>();
        ON_CALL(*m_allowedFields, check(_, _)).WillByDefault(Return(true));

        Context context;
        context.assetName = "decoder/test/0";
        context.policyName = "policy/test/0";
        context.originSpace = "test";
        context.indexDiscardedEvents = false;
        context.indexUnclassifiedEvents = false;

        m_buildCtx = std::make_shared<BuildCtx>(false,           // isTestMode
                                                context,         // context
                                                m_registry,      // registry
                                                m_definitions,   // definitions
                                                m_schema,        // schema validator
                                                m_allowedFields, // allowed fields
                                                nullptr,         // store namespace reader
                                                false);          // allowMissingDependencies
    }

    /** @brief Build one `field: expression` map entry exactly as the map stage does. */
    base::Expression buildMapEntry(const std::string& definition) const
    {
        return baseHelperBuilder(json::Json(definition.c_str()), m_buildCtx, HelperType::MAP);
    }

    /** @brief Run a built map entry (a single term) over an event. */
    static base::result::Result<base::Event> run(const base::Expression& expr, const base::Event& event)
    {
        if (!expr->isTerm())
        {
            throw std::runtime_error("Expected a term expression");
        }
        auto term = expr->getPtr<base::Term<base::EngineOp>>();
        return term->getFn()(event);
    }

    /** @brief Event with `event.received` set to the given JSON value. */
    static base::Event makeEvent(const std::string& receivedJson)
    {
        auto event = std::make_shared<json::Json>(R"({})");
        event->set("/event/received", json::Json(receivedJson.c_str()));
        return event;
    }
};

TEST_F(DateNanosCompatTest, ParseDateAndGetDateIntoDateNanosBuild)
{
    // DATE helpers into a DATE_NANOS field: compatible without runtime validation
    // Delimited raw strings: `()"` and `')"` inside the expressions would otherwise close a plain R"(...)"
    EXPECT_NO_THROW(buildMapEntry(R"json({"event.received": "parse_date($msg, '%Y-%m-%dT%H:%M:%SZ')"})json"));
    EXPECT_NO_THROW(buildMapEntry(R"json({"event.received": "get_date()"})json"));
}

TEST_F(DateNanosCompatTest, DateNanosReferenceIntoDateRuntime)
{
    base::Expression expr;
    ASSERT_NO_THROW(expr = buildMapEntry(R"({"@timestamp": "$event.received"})"));

    const std::vector<std::string> accepted {
        R"("2026-10-26T10:00:00.123456789Z")", R"(["2026-10-26T10:00:00.123456789Z"])", R"([])"};
    for (const auto& value : accepted)
    {
        SCOPED_TRACE(value);
        auto event = makeEvent(value);
        auto result = run(expr, event);
        EXPECT_TRUE(result.success());
        ASSERT_TRUE(event->exists("/@timestamp"));
        EXPECT_EQ(event->getJson("/@timestamp").value().str(), json::Json(value.c_str()).str());
    }
}

TEST_F(DateNanosCompatTest, DateNanosReferenceIntoDateRuntimeRejects)
{
    base::Expression expr;
    ASSERT_NO_THROW(expr = buildMapEntry(R"({"@timestamp": "$event.received"})"));

    // asArray semantics: a scalar is validated directly, an array element by element
    const std::vector<std::string> rejected {R"("not-a-date")", R"(5)", R"(["not-a-date"])", R"([5])"};
    for (const auto& value : rejected)
    {
        SCOPED_TRACE(value);
        auto event = makeEvent(value);
        auto result = run(expr, event);
        EXPECT_TRUE(result.failure());
        EXPECT_FALSE(event->exists("/@timestamp"));
    }
}

TEST_F(DateNanosCompatTest, SystemEpochIsLongRejectedIntoDateRunsIntoLong)
{
    // system_epoch writes integer seconds and is registered as LONG: with DATE<->DATE_NANOS compatibility in place it
    // must still be rejected at build time into a DATE field, and build and run into a LONG field.
    EXPECT_THROW(buildMapEntry(R"json({"@timestamp": "system_epoch()"})json"), std::runtime_error);

    base::Expression expr;
    ASSERT_NO_THROW(expr = buildMapEntry(R"json({"event.sequence": "system_epoch()"})json"));

    auto event = std::make_shared<json::Json>(R"({})");
    auto result = run(expr, event);
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(event->exists("/event/sequence"));
    EXPECT_TRUE(event->isInt64("/event/sequence"));
}

} // namespace
