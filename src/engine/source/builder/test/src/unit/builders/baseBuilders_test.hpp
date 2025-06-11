#ifndef _BUILDER_TEST_BASEBUILDERS_HPP
#define _BUILDER_TEST_BASEBUILDERS_HPP

#include <gtest/gtest.h>

#include <base/behaviour.hpp>

#include "builders/types.hpp"
#include "mockBuildCtx.hpp"
#include "mockRegistry.hpp"

#include <builder/mockAllowedFields.hpp>
#include <defs/mockDefinitions.hpp>
#include <schemf/mockSchema.hpp>

using namespace base::test;
using namespace builder::builders;
using namespace builder::mocks;
using namespace builder::builders::mocks;
using namespace schemf::mocks;
using namespace defs::mocks;

const static auto IGNORE_MAP_RESULT = json::Json("null");

template<typename Builder, typename Expected>
using BuilderT = std::tuple<std::vector<OpArg>, Builder, Expected>;

template<typename Builder, typename Expected>
using OperationT = std::tuple<std::string, Builder, std::string, std::vector<OpArg>, Expected>;

template<typename Builder>
using BuilderWithDeps = std::function<Builder(void)>;

struct BuildersMocks
{
    std::shared_ptr<const MockBuildCtx> ctx;
    std::shared_ptr<RunState> runState;
    std::shared_ptr<MockSchema> validator;
    std::shared_ptr<MockMetaRegistry<OpBuilderEntry, StageBuilder>> registry;
    std::shared_ptr<MockDefinitions> definitions;
    std::shared_ptr<MockAllowedFields> allowedFields;
    Context context;
};

class BaseBuilderTest : public testing::Test
{
protected:
    std::shared_ptr<BuildersMocks> mocks;

    void SetUp() override
    {
        mocks = std::make_shared<BuildersMocks>();
        mocks->ctx = std::make_shared<const MockBuildCtx>();
        mocks->runState = std::make_shared<RunState>();
        mocks->validator = std::make_shared<MockSchema>();
        mocks->registry = MockMetaRegistry<OpBuilderEntry, StageBuilder>::createMock();
        mocks->definitions = std::make_shared<MockDefinitions>();
        mocks->allowedFields = std::make_shared<MockAllowedFields>();

        ON_CALL(*mocks->ctx, context()).WillByDefault(testing::ReturnRef(mocks->context));
        ON_CALL(*mocks->ctx, runState()).WillByDefault(testing::Return(mocks->runState));
        ON_CALL(*mocks->ctx, validator()).WillByDefault(testing::ReturnRef(*(mocks->validator)));
        ON_CALL(*mocks->ctx, allowedFields()).WillByDefault(testing::ReturnRef(*(mocks->allowedFields)));

        ON_CALL(*mocks->allowedFields, check(testing::_, testing::_)).WillByDefault(testing::Return(true));
        ON_CALL(*mocks->ctx, allowedFieldsPtr()).WillByDefault(testing::Return(mocks->allowedFields));

        mocks->context.policyName = "policy/name/0";
        mocks->context.assetName = "asset/name/0";
    }

    void expectBuildSuccess()
    {
        EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks->ctx, runState()).Times(testing::AtLeast(1));
    }
};

template<typename TestClass>
auto testNameFormatter(const std::string& builderName)
{
    return [=](const testing::TestParamInfo<typename TestClass::ParamType>& info)
    {
        return builderName + "_" + std::to_string(info.index);
    };
}

inline OpArg makeValue()
{
    return std::make_shared<Value>();
}

inline OpArg makeValue(const std::string& value)
{
    return std::make_shared<Value>(json::Json(value.c_str()));
}

template<typename... Args>
auto makeRef(Args&&... args)
{
    return std::make_shared<Reference>(std::forward<Args>(args)...);
}

inline auto makeEvent(const std::string& value)
{
    return std::make_shared<json::Json>(value.c_str());
}

namespace filterbuildtest
{
using SuccessExpected = InnerExpected<None, const BuildersMocks&>;
using FailureExpected = InnerExpected<None, const BuildersMocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using FilterT = BuilderT<FilterBuilder, Expc>;

class FilterBuilderTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<FilterT>
{
};

using BuilderGetter = BuilderWithDeps<FilterBuilder>;
using FilterDepsT = BuilderT<BuilderGetter, Expc>;

class FilterBuilderWithDepsTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<FilterDepsT>
{
};
} // namespace filterbuildtest

namespace filteroperatestest
{
using SuccessExpected = InnerExpected<None, const BuildersMocks&>;
using FailureExpected = InnerExpected<None, const BuildersMocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using FilterT = OperationT<FilterBuilder, Expc>;

class FilterOperationTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<FilterT>
{
};

using BuilderGetter = BuilderWithDeps<FilterBuilder>;
using FilterDepsT = OperationT<BuilderGetter, Expc>;

class FilterOperationWithDepsTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<FilterDepsT>
{
};
} // namespace filteroperatestest

namespace mapbuildtest
{
using SuccessExpected = InnerExpected<None, const BuildersMocks&>;
using FailureExpected = InnerExpected<None, const BuildersMocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using MapT = BuilderT<MapBuilder, Expc>;

class MapBuilderTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<MapT>
{
};

using BuilderGetter = BuilderWithDeps<MapBuilder>;
using MapDepsT = BuilderT<BuilderGetter, Expc>;

class MapBuilderWithDepsTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<MapDepsT>
{
};
} // namespace mapbuildtest

namespace mapoperatestest
{
using SuccessExpected = InnerExpected<json::Json, const BuildersMocks&>;
using FailureExpected = InnerExpected<None, const BuildersMocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using MapT = std::tuple<std::string, MapBuilder, std::vector<OpArg>, Expc>;

class MapOperationTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<MapT>
{
};

using BuilderGetter = BuilderWithDeps<MapBuilder>;
using MapDepsT = std::tuple<std::string, BuilderGetter, std::vector<OpArg>, Expc>;

class MapOperationWithDepsTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<MapDepsT>
{
};
} // namespace mapoperatestest

namespace transformbuildtest
{
using SuccessExpected = InnerExpected<None, const BuildersMocks&>;
using FailureExpected = InnerExpected<None, const BuildersMocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using TransformT = BuilderT<TransformBuilder, Expc>;
class TransformBuilderTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<TransformT>
{
};

using BuilderGetter = BuilderWithDeps<TransformBuilder>;
using TransformDepsT = BuilderT<BuilderGetter, Expc>;

class TransformBuilderWithDepsTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<TransformDepsT>
{
};
} // namespace transformbuildtest

namespace transformoperatestest
{
using SuccessExpected = InnerExpected<base::Event, const BuildersMocks&>;
using FailureExpected = InnerExpected<None, const BuildersMocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using TransformT = OperationT<TransformBuilder, Expc>;

class TransformOperationTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<TransformT>
{
};

using BuilderGetter = BuilderWithDeps<TransformBuilder>;
using TransformDepsT = OperationT<BuilderGetter, Expc>;

class TransformOperationWithDepsTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<TransformDepsT>
{
};
} // namespace transformoperatestest

template<typename Builder>
auto expectFilterHelper(const std::string& name, Builder builder)
{
    return [=](const BuildersMocks& mocks)
    {
        const auto& innerRegistry = mocks.registry->getRegistry<Builder>();
        std::shared_ptr<MockBuildCtx> ctx = std::make_shared<MockBuildCtx>();
        EXPECT_CALL(*mocks.ctx, clone()).WillOnce(testing::Return(ctx));

        EXPECT_CALL(*ctx, context()).WillOnce(testing::ReturnRefOfCopy(mocks.context));
        EXPECT_CALL(*ctx, validator()).Times(testing::AtLeast(1)).WillRepeatedly(testing::ReturnRef(*mocks.validator));
        EXPECT_CALL(*mocks.validator, validate(testing::_, testing::_))
            .Times(testing::AtLeast(1))
            .WillRepeatedly(testing::Return(schemf::ValidationResult()));

        EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
        EXPECT_CALL(innerRegistry, get(name)).WillOnce(testing::Return(builder));

        return None {};
    };
}

template<typename Builder>
auto expectMapHelper(const std::string& name, Builder builder)
{
    return [=](const BuildersMocks& mocks)
    {
        const auto& innerRegistry = mocks.registry->getRegistry<Builder>();
        std::shared_ptr<MockBuildCtx> ctx = std::make_shared<MockBuildCtx>();
        EXPECT_CALL(*mocks.ctx, clone()).WillOnce(testing::Return(ctx));

        EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRefOfCopy(mocks.context));
        std::shared_ptr<const MockBuildCtx> constCtx = ctx;
        EXPECT_CALL(*constCtx, context()).WillRepeatedly(testing::ReturnRefOfCopy(mocks.context));

        EXPECT_CALL(*constCtx, allowedFields()).WillOnce(testing::ReturnRef(*mocks.allowedFields));
        EXPECT_CALL(*mocks.allowedFields, check(testing::_, testing::_)).WillOnce(testing::Return(true));

        EXPECT_CALL(*ctx, validator()).Times(testing::AtLeast(1)).WillRepeatedly(testing::ReturnRef(*mocks.validator));
        EXPECT_CALL(*mocks.validator, validate(testing::_, testing::_))
            .Times(testing::AtLeast(1))
            .WillRepeatedly(testing::Return(schemf::ValidationResult()));

        EXPECT_CALL(*mocks.ctx, registry()).WillOnce(testing::ReturnRef(*mocks.registry));
        EXPECT_CALL(innerRegistry, get(name)).WillOnce(testing::Return(builder));

        return None {};
    };
}

template<typename Builder>
auto expectTransformHelper(const std::string& name, Builder builder)
{
    return expectFilterHelper(name, builder);
}

template<typename Builder>
struct Helper
{
    std::string name;
    Builder builder;
};

template<typename Builder, typename... Builders>
auto expectAnyFilterHelper(Builders... builders)
{
    return [=](const BuildersMocks& mocks)
    {
        const auto& innerRegistry = mocks.registry->getRegistry<Builder>();
        std::shared_ptr<MockBuildCtx> ctx = std::make_shared<MockBuildCtx>();
        EXPECT_CALL(*mocks.ctx, clone()).WillRepeatedly(testing::Return(ctx));

        EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRefOfCopy(mocks.context));
        EXPECT_CALL(*ctx, validator()).Times(testing::AtLeast(1)).WillRepeatedly(testing::ReturnRef(*mocks.validator));
        EXPECT_CALL(*mocks.validator, validate(testing::_, testing::_))
            .Times(testing::AtLeast(1))
            .WillRepeatedly(testing::Return(schemf::ValidationResult()));

        EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));

        (
            [&]()
            {
                std::string name = builders.name;
                Builder builder = builders.builder;
                EXPECT_CALL(innerRegistry, get(name)).WillOnce(testing::Return(builder));
            }(),
            ...);

        return None {};
    };
}

template<typename Builder, typename... Builders>
auto expectAnyMapHelper(Builders... builders)
{
    return [=](const BuildersMocks& mocks)
    {
        const auto& innerRegistry = mocks.registry->getRegistry<Builder>();
        std::shared_ptr<MockBuildCtx> ctx = std::make_shared<MockBuildCtx>();
        EXPECT_CALL(*mocks.ctx, clone()).WillRepeatedly(testing::Return(ctx));

        EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRefOfCopy(mocks.context));
        std::shared_ptr<const MockBuildCtx> constCtx = ctx;
        EXPECT_CALL(*constCtx, context()).WillRepeatedly(testing::ReturnRefOfCopy(mocks.context));

        EXPECT_CALL(*constCtx, allowedFields()).WillRepeatedly(testing::ReturnRef(*mocks.allowedFields));
        EXPECT_CALL(*mocks.allowedFields, check(testing::_, testing::_)).WillRepeatedly(testing::Return(true));

        EXPECT_CALL(*ctx, validator()).Times(testing::AtLeast(1)).WillRepeatedly(testing::ReturnRef(*mocks.validator));
        EXPECT_CALL(*mocks.validator, validate(testing::_, testing::_))
            .Times(testing::AtLeast(1))
            .WillRepeatedly(testing::Return(schemf::ValidationResult()));

        EXPECT_CALL(*mocks.ctx, registry()).WillRepeatedly(testing::ReturnRef(*mocks.registry));

        (
            [&]()
            {
                std::string name = builders.name;
                Builder builder = builders.builder;
                EXPECT_CALL(innerRegistry, get(name)).WillOnce(testing::Return(builder));
            }(),
            ...);

        return None {};
    };
}

inline auto dummyTerm(const std::string& name)
{
    return base::Term<TransformOp>::create(
        name, [](base::Event e) -> TransformResult { return base::result::makeSuccess(e, ""); });
}

namespace stagebuildtest
{
using SuccessExpected = InnerExpected<base::Expression, const BuildersMocks&>;
using FailureExpected = InnerExpected<None, const BuildersMocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using StageT = std::tuple<std::string, StageBuilder, Expc>;

class StageBuilderTest
    : public BaseBuilderTest
    , public testing::WithParamInterface<StageT>
{
};

} // namespace stagebuildtest

#endif // _BUILDER_TEST_BASEBUILDERS_HPP
