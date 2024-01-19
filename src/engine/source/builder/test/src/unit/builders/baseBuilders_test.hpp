#ifndef _BUILDER_TEST_BASEBUILDERS_HPP
#define _BUILDER_TEST_BASEBUILDERS_HPP

#include <gtest/gtest.h>

#include <base/test/behaviour.hpp>

#include "builders/types.hpp"
#include "mockBuildCtx.hpp"
#include <schemf/mockSchema.hpp>
#include <schemval/mockValidator.hpp>

using namespace base::test;
using namespace builder::builders;
using namespace builder::builders::mocks;
using namespace schemf::mocks;
using namespace schemval::mocks;

template<typename Builder, typename Expected>
using BuilderT = std::tuple<std::vector<OpArg>, Builder, Expected>;

template<typename Builder, typename Expected>
using OperationT = std::tuple<std::string, Builder, std::string, std::vector<OpArg>, Expected>;

struct BuildersMocks
{
    std::shared_ptr<const MockBuildCtx> ctx;
    std::shared_ptr<const RunState> runState;
    std::shared_ptr<MockSchema> schema;
    std::shared_ptr<MockValidator> validator;
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
        mocks->runState = std::make_shared<const RunState>();
        mocks->schema = std::make_shared<MockSchema>();
        mocks->validator = std::make_shared<MockValidator>();

        ON_CALL(*mocks->ctx, context()).WillByDefault(testing::ReturnRef(mocks->context));
        ON_CALL(*mocks->ctx, runState()).WillByDefault(testing::Return(mocks->runState));
        ON_CALL(*mocks->ctx, schema()).WillByDefault(testing::ReturnRef(*(mocks->schema)));
        ON_CALL(*mocks->ctx, validator()).WillByDefault(testing::ReturnRef(*(mocks->validator)));
    }

    void TearDown() override
    {
        mocks->validator.reset();
        mocks->schema.reset();
        mocks->runState.reset();
        mocks->ctx.reset();
        mocks.reset();
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
} // namespace transformoperatestest

#endif // _BUILDER_TEST_BASEBUILDERS_HPP
