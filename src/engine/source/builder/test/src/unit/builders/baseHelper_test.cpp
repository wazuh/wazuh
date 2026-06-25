#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <base/behaviour.hpp>
#include <base/expression.hpp>
#include <fastmetrics/mockManager.hpp>
#include <fastmetrics/registry.hpp>

#include "builders/baseHelper.hpp"
#include "builders/types.hpp"
#include "mockBuildCtx.hpp"
#include "mockRegistry.hpp"

#include <builder/mockAllowedFields.hpp>
#include <defs/mockDefinitions.hpp>
#include <schemf/mockSchema.hpp>

using namespace base::test;
using namespace builder::builders;
using namespace builder::builders::mocks;
using namespace builder::mocks;
using namespace schemf::mocks;
using namespace defs::mocks;
using testing::AtLeast;
using testing::Const;
using testing::Invoke;
using testing::Matcher;
using testing::Return;
using testing::ReturnRef;
using testing::ReturnRefOfCopy;
using testing::_;

/***************************
 * Test fixture
 ***************************/
class BaseHelperTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockBuildCtx> ctx;
    std::shared_ptr<MockSchema> validator;
    std::shared_ptr<MockMetaRegistry<OpBuilderEntry, StageBuilder, EnrichmentBuilder>> registry;
    std::shared_ptr<MockDefinitions> definitions;
    std::shared_ptr<MockAllowedFields> allowedFields;
    Context context;

    void SetUp() override
    {
        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();

        ctx = std::make_shared<MockBuildCtx>();
        validator = std::make_shared<MockSchema>();
        registry = MockMetaRegistry<OpBuilderEntry, StageBuilder, EnrichmentBuilder>::createMock();
        definitions = std::make_shared<MockDefinitions>();
        allowedFields = std::make_shared<MockAllowedFields>();

        context.policyName = "policy/name/0";
        context.originSpace = "test_space";
        context.assetName = "asset/name/0";

        ON_CALL(*ctx, context()).WillByDefault(ReturnRef(context));
        ON_CALL(Const(*ctx), context()).WillByDefault(ReturnRef(context));
        ON_CALL(*ctx, isTestMode()).WillByDefault(Return(false));
        ON_CALL(*ctx, validator()).WillByDefault(ReturnRef(*validator));
        ON_CALL(*ctx, allowedFields()).WillByDefault(ReturnRef(*allowedFields));
        ON_CALL(*ctx, definitions()).WillByDefault(ReturnRef(*definitions));
        ON_CALL(*ctx, registry()).WillByDefault(ReturnRef(*registry));
        ON_CALL(*allowedFields, check(_, _)).WillByDefault(Return(true));
    }

    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }

    // Helper: create a simple MapBuilder that returns a fixed value
    MapBuilder makeSimpleMapBuilder(json::Json result = json::Json(R"_j("ok")_j"))
    {
        return [result](const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&) -> MapOp
        {
            return [result](base::ConstEvent) -> MapResult { return base::result::makeSuccess(result, "success"); };
        };
    }

    // Helper: create a MapBuilder that always fails
    MapBuilder makeFailMapBuilder()
    {
        return [](const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&) -> MapOp
        {
            return [](base::ConstEvent) -> MapResult
            { return base::result::makeFailure(json::Json(), "mapFail"); };
        };
    }

    // Helper: create a simple FilterBuilder
    FilterBuilder makeSimpleFilterBuilder(bool pass = true)
    {
        return [pass](const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&) -> FilterOp
        {
            return [pass](base::ConstEvent) -> FilterResult
            {
                if (pass)
                    return base::result::makeSuccess(true, "filterPass");
                else
                    return base::result::makeFailure(false, "filterFail");
            };
        };
    }

    // Helper: create a simple TransformBuilder
    TransformBuilder makeSimpleTransformBuilder()
    {
        return [](const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&) -> TransformOp
        {
            return [](base::Event e) -> TransformResult { return base::result::makeSuccess(e, "transformOk"); };
        };
    }

    // Setup registry to return a given OpBuilderEntry for a helper name
    void setupRegistry(const std::string& name, const OpBuilder& builder, ValidationInfo valInfo = schemf::ValidationToken{})
    {
        OpBuilderEntry entry {valInfo, builder};
        auto& innerRegistry = registry->getRegistry<OpBuilderEntry>();
        EXPECT_CALL(innerRegistry, get(name)).WillOnce(Return(entry));
    }

    // Setup registry to return an error (helper not found)
    void setupRegistryNotFound(const std::string& name)
    {
        auto& innerRegistry = registry->getRegistry<OpBuilderEntry>();
        EXPECT_CALL(innerRegistry, get(name)).WillOnce(Return(getError<OpBuilderEntry>()));
    }

    // Setup clone to return a usable mock
    std::shared_ptr<MockBuildCtx> setupClone()
    {
        auto cloneCtx = std::make_shared<MockBuildCtx>();
        EXPECT_CALL(*ctx, clone()).WillOnce(Return(cloneCtx));
        ON_CALL(*cloneCtx, context()).WillByDefault(ReturnRef(context));
        ON_CALL(Const(*cloneCtx), context()).WillByDefault(ReturnRef(context));
        ON_CALL(*cloneCtx, isTestMode()).WillByDefault(Return(false));
        ON_CALL(*cloneCtx, validator()).WillByDefault(ReturnRef(*validator));
        ON_CALL(*cloneCtx, allowedFields()).WillByDefault(ReturnRef(*allowedFields));
        return cloneCtx;
    }

    // Setup schema validation to pass with no runtime validation
    void setupValidationOk()
    {
        EXPECT_CALL(*validator, validate(Matcher<const DotPath&>(_), Matcher<const schemf::ValidationToken&>(_)))
            .WillRepeatedly(Return(schemf::ValidationResult()));
    }
};

/***************************
 * Section 1: buildType tests
 ***************************/

TEST_F(BaseHelperTest, BuildTypeValidationError)
{
    // When schema validation returns error, buildType should throw
    auto builder = OpBuilder{makeSimpleMapBuilder()};
    Reference targetField("target.field");
    schemf::ValidationToken token;

    EXPECT_CALL(*validator, validate(Matcher<const DotPath&>(_), Matcher<const schemf::ValidationToken&>(_)))
        .WillOnce(Return(base::Error{"Schema validation failed"}));

    ASSERT_THROW(buildType(builder, targetField, token, *validator), std::runtime_error);
}

TEST_F(BaseHelperTest, BuildTypeNoRuntimeValidation)
{
    // When validation passes without needing runtime validation, builder is returned as-is
    auto mapBuilder = makeSimpleMapBuilder();
    OpBuilder builder{mapBuilder};
    Reference targetField("target.field");
    schemf::ValidationToken token;

    // Return a ValidationResult that does NOT need runtime validation
    EXPECT_CALL(*validator, validate(Matcher<const DotPath&>(_), Matcher<const schemf::ValidationToken&>(_)))
        .WillOnce(Return(schemf::ValidationResult()));

    auto result = buildType(builder, targetField, token, *validator);
    // The builder variant index should remain the same (MapBuilder = 0)
    ASSERT_EQ(result.index(), 0u);
}

TEST_F(BaseHelperTest, BuildTypeWithRuntimeValidation)
{
    // When validation needs runtime validation, builder should be wrapped by runType
    auto mapBuilder = makeSimpleMapBuilder();
    OpBuilder builder{mapBuilder};
    Reference targetField("target.field");
    schemf::ValidationToken token;

    // Construct a ValidationResult that DOES need runtime validation
    schemf::ValidationResult valResult([](const json::Json&) -> base::OptError { return std::nullopt; });

    EXPECT_CALL(*validator, validate(Matcher<const DotPath&>(_), Matcher<const schemf::ValidationToken&>(_)))
        .WillOnce(Return(valResult));

    auto result = buildType(builder, targetField, token, *validator);
    // It should still be MapBuilder (index 0), but wrapped
    ASSERT_EQ(result.index(), 0u);
}

/***************************
 * Section 2: runType tests
 ***************************/

TEST_F(BaseHelperTest, RunTypeNonMapBuilderPassthrough)
{
    // runType should return as-is if the builder is not a MapBuilder (e.g., FilterBuilder)
    OpBuilder builder{makeSimpleFilterBuilder()};
    Reference targetField("target.field");
    schemf::ValidationResult valResult([](const json::Json&) -> base::OptError { return std::nullopt; });

    auto result = runType(builder, targetField, valResult);
    // Should remain a FilterBuilder (index 2)
    ASSERT_EQ(result.index(), 2u);
}

TEST_F(BaseHelperTest, RunTypeMapBuilderWrapped)
{
    // runType wraps a MapBuilder with runtime validation
    OpBuilder builder{makeSimpleMapBuilder(json::Json(R"_j("hello")_j"))};
    Reference targetField("target.field");
    schemf::ValidationResult valResult([](const json::Json&) -> base::OptError { return std::nullopt; });

    auto result = runType(builder, targetField, valResult);
    ASSERT_EQ(result.index(), 0u); // Still MapBuilder

    // The wrapped builder should work: build and invoke the MapOp
    auto wrappedMapBuilder = std::get<MapBuilder>(result);
    auto mapOp = wrappedMapBuilder({}, ctx);
    auto event = std::make_shared<json::Json>(R"({})");
    auto mapResult = mapOp(event);
    ASSERT_TRUE(mapResult.success());
}

TEST_F(BaseHelperTest, RunTypeRuntimeValidationFails)
{
    // runType wraps a MapBuilder; runtime validation returns error
    OpBuilder builder{makeSimpleMapBuilder(json::Json(R"_j("bad")_j"))};
    Reference targetField("target.field");
    schemf::ValidationResult valResult([](const json::Json&) -> base::OptError {
        return base::Error{"runtime validation failed"};
    });

    auto result = runType(builder, targetField, valResult);
    ASSERT_EQ(result.index(), 0u);

    auto wrappedMapBuilder = std::get<MapBuilder>(result);
    ON_CALL(*ctx, isTestMode()).WillByDefault(Return(true)); // Need test mode to get trace
    auto mapOp = wrappedMapBuilder({}, ctx);
    auto event = std::make_shared<json::Json>(R"({})");
    auto mapResult = mapOp(event);
    ASSERT_TRUE(mapResult.failure());
}

TEST_F(BaseHelperTest, RunTypeInnerMapFails)
{
    // runType wraps a MapBuilder; the inner map fails -> wrapped should also fail
    OpBuilder builder{makeFailMapBuilder()};
    Reference targetField("target.field");
    schemf::ValidationResult valResult([](const json::Json&) -> base::OptError { return std::nullopt; });

    auto result = runType(builder, targetField, valResult);
    ASSERT_EQ(result.index(), 0u);

    auto wrappedMapBuilder = std::get<MapBuilder>(result);
    auto mapOp = wrappedMapBuilder({}, ctx);
    auto event = std::make_shared<json::Json>(R"({})");
    auto mapResult = mapOp(event);
    ASSERT_TRUE(mapResult.failure());
}

/***************************
 * Section 3: filterToTransform tests
 ***************************/

TEST_F(BaseHelperTest, FilterToTransformSuccess)
{
    auto filterBuilder = makeSimpleFilterBuilder(true);
    auto transformBuilder = filterToTransform(filterBuilder);

    Reference targetField("target.field");
    auto transformOp = transformBuilder(targetField, {}, ctx);

    auto event = std::make_shared<json::Json>(R"({"key": "value"})");
    auto result = transformOp(event);
    ASSERT_TRUE(result.success());
}

TEST_F(BaseHelperTest, FilterToTransformFailure)
{
    auto filterBuilder = makeSimpleFilterBuilder(false);
    auto transformBuilder = filterToTransform(filterBuilder);

    Reference targetField("target.field");
    ON_CALL(*ctx, isTestMode()).WillByDefault(Return(true));
    auto transformOp = transformBuilder(targetField, {}, ctx);

    auto event = std::make_shared<json::Json>(R"({"key": "value"})");
    auto result = transformOp(event);
    ASSERT_TRUE(result.failure());
}

/***************************
 * Section 4: mapToTransform tests
 ***************************/

TEST_F(BaseHelperTest, MapToTransformSuccess)
{
    auto mapBuilder = makeSimpleMapBuilder(json::Json(R"_j("mapped_value")_j"));
    auto transformBuilder = mapToTransform(mapBuilder, Reference("target.field"));

    Reference ignored("ignored");
    auto transformOp = transformBuilder(ignored, {}, ctx);

    auto event = std::make_shared<json::Json>(R"({})");
    auto result = transformOp(event);
    ASSERT_TRUE(result.success());

    // The target field should now be set
    std::string value;
    result.payload()->getString(value, "/target/field");
    ASSERT_EQ(value, "mapped_value");
}

TEST_F(BaseHelperTest, MapToTransformFailure)
{
    auto mapBuilder = makeFailMapBuilder();
    auto transformBuilder = mapToTransform(mapBuilder, Reference("target.field"));

    Reference ignored("ignored");
    ON_CALL(*ctx, isTestMode()).WillByDefault(Return(true));
    auto transformOp = transformBuilder(ignored, {}, ctx);

    auto event = std::make_shared<json::Json>(R"({})");
    auto result = transformOp(event);
    ASSERT_TRUE(result.failure());
}

TEST_F(BaseHelperTest, MapToTransformDisallowedField)
{
    auto mapBuilder = makeSimpleMapBuilder();
    auto transformBuilder = mapToTransform(mapBuilder, Reference("target.field"));

    Reference ignored("ignored");
    EXPECT_CALL(*allowedFields, check(_, _)).WillOnce(Return(false));
    ASSERT_THROW(transformBuilder(ignored, {}, ctx), std::runtime_error);
}

/***************************
 * Section 5: toTransform tests
 ***************************/

TEST_F(BaseHelperTest, ToTransformFromMapBuilder)
{
    OpBuilder builder{makeSimpleMapBuilder()};
    Reference targetField("target.field");
    auto result = toTransform(builder, targetField);
    // Should produce a TransformBuilder that can be called
    auto transformOp = result(targetField, {}, ctx);
    auto event = std::make_shared<json::Json>(R"({})");
    ASSERT_TRUE(transformOp(event).success());
}

TEST_F(BaseHelperTest, ToTransformFromTransformBuilder)
{
    auto tb = makeSimpleTransformBuilder();
    OpBuilder builder{tb};
    Reference targetField("target.field");
    auto result = toTransform(builder, targetField);
    auto transformOp = result(targetField, {}, ctx);
    auto event = std::make_shared<json::Json>(R"({})");
    ASSERT_TRUE(transformOp(event).success());
}

TEST_F(BaseHelperTest, ToTransformFromFilterBuilder)
{
    OpBuilder builder{makeSimpleFilterBuilder()};
    Reference targetField("target.field");
    auto result = toTransform(builder, targetField);
    auto transformOp = result(targetField, {}, ctx);
    auto event = std::make_shared<json::Json>(R"({})");
    ASSERT_TRUE(transformOp(event).success());
}

/***************************
 * Section 6: baseHelperBuilder (name-based overload) tests
 ***************************/

TEST_F(BaseHelperTest, BaseHelperBuilderMapSuccess)
{
    Reference targetField("target.field");
    std::vector<OpArg> opArgs;
    json::Json helloJson(R"("hello")");
    opArgs.emplace_back(std::make_shared<Value>(helloJson));

    setupRegistry("testHelper", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder("testHelper", targetField, opArgs, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, BaseHelperBuilderFilterSuccess)
{
    Reference targetField("target.field");
    std::vector<OpArg> opArgs;

    setupRegistry("testFilter", OpBuilder{makeSimpleFilterBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder("testFilter", targetField, opArgs, ctx, HelperType::FILTER);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, BaseHelperBuilderHelperNotFound)
{
    Reference targetField("target.field");
    std::vector<OpArg> opArgs;

    setupRegistryNotFound("unknownHelper");
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    ASSERT_THROW(baseHelperBuilder("unknownHelper", targetField, opArgs, ctx, HelperType::MAP), std::runtime_error);
}

TEST_F(BaseHelperTest, BaseHelperBuilderTypeMismatchMapExpectsFilter)
{
    // Register a MapBuilder but request FILTER
    Reference targetField("target.field");
    std::vector<OpArg> opArgs;

    setupRegistry("testHelper", OpBuilder{makeSimpleMapBuilder()});
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    ASSERT_THROW(baseHelperBuilder("testHelper", targetField, opArgs, ctx, HelperType::FILTER), std::runtime_error);
}

TEST_F(BaseHelperTest, BaseHelperBuilderTypeMismatchFilterExpectsMap)
{
    // Register a FilterBuilder but request MAP
    Reference targetField("target.field");
    std::vector<OpArg> opArgs;

    setupRegistry("testHelper", OpBuilder{makeSimpleFilterBuilder()});
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    ASSERT_THROW(baseHelperBuilder("testHelper", targetField, opArgs, ctx, HelperType::MAP), std::runtime_error);
}

TEST_F(BaseHelperTest, BaseHelperBuilderResolvesDefinition)
{
    // When an opArg is a reference that matches a definition, it should be resolved to a Value
    Reference targetField("target.field");
    auto ref = std::make_shared<Reference>("some.def.path");
    std::vector<OpArg> opArgs;
    opArgs.emplace_back(ref);

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));
    EXPECT_CALL(*definitions, contains("/some/def/path")).WillOnce(Return(true));
    EXPECT_CALL(*definitions, get("/some/def/path")).WillOnce(Return(json::Json(R"_j("resolved_value")_j")));

    setupRegistry("testHelper", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();

    auto expr = baseHelperBuilder("testHelper", targetField, opArgs, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
    // After resolution, the opArg should have been replaced with a Value
    ASSERT_FALSE(opArgs[0]->isReference());
}

TEST_F(BaseHelperTest, BaseHelperBuilderDynamicValidationToken)
{
    Reference targetField("target.field");
    std::vector<OpArg> opArgs;

    // Use a DynamicValToken
    DynamicValToken dynamicToken = [](const std::vector<OpArg>&, const schemf::IValidator&) -> schemf::ValidationToken
    {
        return schemf::ValidationToken {};
    };

    ValidationInfo valInfo {dynamicToken};
    setupRegistry("testHelper", OpBuilder{makeSimpleMapBuilder()}, valInfo);
    setupValidationOk();
    auto cloneCtx = setupClone();

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder("testHelper", targetField, opArgs, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, BaseHelperBuilderTransformBuilderAsMap)
{
    // A TransformBuilder should be accepted for MAP helper type
    Reference targetField("target.field");
    std::vector<OpArg> opArgs;

    setupRegistry("testHelper", OpBuilder{makeSimpleTransformBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder("testHelper", targetField, opArgs, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

/***************************
 * Section 7: baseHelperBuilder (JSON definition overload) tests
 ***************************/

TEST_F(BaseHelperTest, JsonDefinitionNotObject)
{
    json::Json def(R"_j("just a string")_j");
    ASSERT_THROW(baseHelperBuilder(def, ctx, HelperType::MAP), std::runtime_error);
}

TEST_F(BaseHelperTest, JsonDefinitionMultipleKeys)
{
    json::Json def(R"({"key1": "val1", "key2": "val2"})");
    ASSERT_THROW(baseHelperBuilder(def, ctx, HelperType::MAP), std::runtime_error);
}

TEST_F(BaseHelperTest, JsonDefinitionNullValueMap)
{
    // null literal is now accepted as a map operation
    json::Json def(R"({"target.field": null})");

    setupRegistry("map", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionNullValueFilter)
{
    // null literal is also accepted in filter/check stages
    json::Json def(R"({"target.field": null})");

    setupRegistry("filter", OpBuilder{makeSimpleFilterBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::FILTER);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionBoolValueMap)
{
    // Bool value with MAP type -> default helper "map"
    json::Json def(R"({"target.field": true})");

    setupRegistry("map", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionBoolValueFilter)
{
    // Bool value with FILTER type -> default helper "filter"
    json::Json def(R"({"target.field": true})");

    setupRegistry("filter", OpBuilder{makeSimpleFilterBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::FILTER);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionNumberValue)
{
    // Number value -> default helper based on type
    json::Json def(R"({"target.field": 42})");

    setupRegistry("map", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionStringReference)
{
    // String value starting with '$' -> reference
    json::Json def(R"({"target.field": "$some.ref.field"})");

    setupRegistry("map", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));
    EXPECT_CALL(*definitions, contains(_)).WillRepeatedly(Return(false));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionStringEscapedReference)
{
    // String value starting with '\$' -> escaped reference, should be a plain value
    json::Json def(R"({"target.field": "\\$not.a.ref"})");

    setupRegistry("map", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionStringHelperExpression)
{
    // String value that is a helper expression: helper_name(args...)
    json::Json def(R"json({"target.field": "int_calculate($other.field)"})json");

    setupRegistry("int_calculate", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));
    EXPECT_CALL(*definitions, contains(_)).WillRepeatedly(Return(false));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionStringPlainValue)
{
    // Plain string (not helper, not reference) -> default helper
    json::Json def(R"({"target.field": "just a plain string"})");

    setupRegistry("map", OpBuilder{makeSimpleMapBuilder()});
    setupValidationOk();
    auto cloneCtx = setupClone();
    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
}

TEST_F(BaseHelperTest, JsonDefinitionArrayValue)
{
    // Array value -> creates sub-expressions for each element
    json::Json def(R"({"target.field": ["value1", "value2"]})");

    // Each array element will recursively call baseHelperBuilder, needing "map" registered
    auto& innerRegistry = registry->getRegistry<OpBuilderEntry>();
    OpBuilderEntry entry{schemf::ValidationToken{}, OpBuilder{makeSimpleMapBuilder()}};
    EXPECT_CALL(innerRegistry, get("map")).WillRepeatedly(Return(entry));

    setupValidationOk();

    // clone() will be called for each array element
    EXPECT_CALL(*ctx, clone()).WillRepeatedly(Invoke([this]() -> std::shared_ptr<IBuildCtx> {
        auto cloneCtx = std::make_shared<MockBuildCtx>();
        ON_CALL(*cloneCtx, context()).WillByDefault(ReturnRef(context));
        ON_CALL(Const(*cloneCtx), context()).WillByDefault(ReturnRef(context));
        ON_CALL(*cloneCtx, isTestMode()).WillByDefault(Return(false));
        ON_CALL(*cloneCtx, validator()).WillByDefault(ReturnRef(*validator));
        ON_CALL(*cloneCtx, allowedFields()).WillByDefault(ReturnRef(*allowedFields));
        return cloneCtx;
    }));

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
    // Should be a Chain expression for MAP
    ASSERT_TRUE(expr->isOperation());
    ASSERT_EQ(expr->getTypeName(), "Chain");
}

TEST_F(BaseHelperTest, JsonDefinitionArrayValueFilter)
{
    // Array with FILTER -> And expression
    json::Json def(R"({"target.field": ["value1", "value2"]})");

    auto& innerRegistry = registry->getRegistry<OpBuilderEntry>();
    OpBuilderEntry entry{schemf::ValidationToken{}, OpBuilder{makeSimpleFilterBuilder()}};
    EXPECT_CALL(innerRegistry, get("filter")).WillRepeatedly(Return(entry));

    setupValidationOk();

    EXPECT_CALL(*ctx, clone()).WillRepeatedly(Invoke([this]() -> std::shared_ptr<IBuildCtx> {
        auto cloneCtx = std::make_shared<MockBuildCtx>();
        ON_CALL(*cloneCtx, context()).WillByDefault(ReturnRef(context));
        ON_CALL(Const(*cloneCtx), context()).WillByDefault(ReturnRef(context));
        ON_CALL(*cloneCtx, isTestMode()).WillByDefault(Return(false));
        ON_CALL(*cloneCtx, validator()).WillByDefault(ReturnRef(*validator));
        ON_CALL(*cloneCtx, allowedFields()).WillByDefault(ReturnRef(*allowedFields));
        return cloneCtx;
    }));

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::FILTER);
    ASSERT_NE(expr, nullptr);
    ASSERT_TRUE(expr->isOperation());
    ASSERT_EQ(expr->getTypeName(), "And");
}

TEST_F(BaseHelperTest, JsonDefinitionObjectValue)
{
    // Object value -> creates sub-expressions with setObjectTerm/deleteEmptyObjectTerm for MAP
    json::Json def(R"({"target.field": {"sub": "value1"}})");

    auto& innerRegistry = registry->getRegistry<OpBuilderEntry>();
    OpBuilderEntry entry{schemf::ValidationToken{}, OpBuilder{makeSimpleMapBuilder()}};
    EXPECT_CALL(innerRegistry, get("map")).WillRepeatedly(Return(entry));

    setupValidationOk();

    EXPECT_CALL(*ctx, clone()).WillRepeatedly(Invoke([this]() -> std::shared_ptr<IBuildCtx> {
        auto cloneCtx = std::make_shared<MockBuildCtx>();
        ON_CALL(*cloneCtx, context()).WillByDefault(ReturnRef(context));
        ON_CALL(Const(*cloneCtx), context()).WillByDefault(ReturnRef(context));
        ON_CALL(*cloneCtx, isTestMode()).WillByDefault(Return(false));
        ON_CALL(*cloneCtx, validator()).WillByDefault(ReturnRef(*validator));
        ON_CALL(*cloneCtx, allowedFields()).WillByDefault(ReturnRef(*allowedFields));
        return cloneCtx;
    }));

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::MAP);
    ASSERT_NE(expr, nullptr);
    ASSERT_TRUE(expr->isOperation());
    ASSERT_EQ(expr->getTypeName(), "Chain");
    // For MAP objects: first child = setObjectTerm, middle = sub-expressions, last = deleteEmptyObjectTerm
    auto op = expr->getPtr<base::Operation>();
    ASSERT_GE(op->getOperands().size(), 3u); // setObjectTerm + 1 child + deleteEmptyObjectTerm
}

TEST_F(BaseHelperTest, JsonDefinitionObjectValueFilter)
{
    // Object value with FILTER -> And expression (no setObject/deleteEmpty)
    json::Json def(R"({"target.field": {"sub": "value1"}})");

    auto& innerRegistry = registry->getRegistry<OpBuilderEntry>();
    OpBuilderEntry entry{schemf::ValidationToken{}, OpBuilder{makeSimpleFilterBuilder()}};
    EXPECT_CALL(innerRegistry, get("filter")).WillRepeatedly(Return(entry));

    setupValidationOk();

    EXPECT_CALL(*ctx, clone()).WillRepeatedly(Invoke([this]() -> std::shared_ptr<IBuildCtx> {
        auto cloneCtx = std::make_shared<MockBuildCtx>();
        ON_CALL(*cloneCtx, context()).WillByDefault(ReturnRef(context));
        ON_CALL(Const(*cloneCtx), context()).WillByDefault(ReturnRef(context));
        ON_CALL(*cloneCtx, isTestMode()).WillByDefault(Return(false));
        ON_CALL(*cloneCtx, validator()).WillByDefault(ReturnRef(*validator));
        ON_CALL(*cloneCtx, allowedFields()).WillByDefault(ReturnRef(*allowedFields));
        return cloneCtx;
    }));

    EXPECT_CALL(*ctx, definitions()).WillRepeatedly(ReturnRef(*definitions));

    auto expr = baseHelperBuilder(def, ctx, HelperType::FILTER);
    ASSERT_NE(expr, nullptr);
    ASSERT_TRUE(expr->isOperation());
    ASSERT_EQ(expr->getTypeName(), "And");
    // For FILTER objects: no setObject/deleteEmpty, just sub-expressions
    auto op = expr->getPtr<base::Operation>();
    ASSERT_EQ(op->getOperands().size(), 1u); // only 1 child for "sub"
}

/***************************
 * Section 8: toExpression test
 ***************************/

TEST_F(BaseHelperTest, ToExpressionCreatesNamedTerm)
{
    TransformOp op = [](base::Event e) -> TransformResult { return base::result::makeSuccess(e, "ok"); };
    auto expr = toExpression(op, "testOp");
    ASSERT_NE(expr, nullptr);
    ASSERT_EQ(expr->getName(), "testOp");
    ASSERT_FALSE(expr->isOperation());
}
