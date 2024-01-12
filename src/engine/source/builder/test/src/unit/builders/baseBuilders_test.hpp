#ifndef _BUILDER_TEST_BASEBUILDERS_HPP
#define _BUILDER_TEST_BASEBUILDERS_HPP

#include <gtest/gtest.h>

#include <base/test/behaviour.hpp>

#include "builders/types.hpp"
#include "mockBuildCtx.hpp"

using namespace base::test;
using namespace builder::builders;
using namespace builder::builders::mocks;

template<typename Builder, typename Expected>
using BuilderT = std::tuple<std::vector<OpArg>, Builder, Expected>;

template<typename Builder, typename Expected>
using OperationT = std::tuple<std::string, Builder, std::string, std::vector<OpArg>, Expected>;

template<typename T>
class BaseBuilderTest : public testing::TestWithParam<T>
{
protected:
    std::shared_ptr<const MockBuildCtx> ctx;
    Context context;
    std::shared_ptr<const RunState> runState;
    void SetUp() override
    {
        ctx = std::make_shared<const MockBuildCtx>();
        runState = std::make_shared<const RunState>();
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

static OpArg makeValue()
{
    return std::make_shared<Value>();
}

static OpArg makeValue(const std::string& value)
{
    return std::make_shared<Value>(json::Json(value.c_str()));
}

template<typename... Args>
auto makeRef(Args&&... args)
{
    return std::make_shared<Reference>(std::forward<Args>(args)...);
}

namespace filterbuildtest
{
using SuccessExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using FilterT = BuilderT<FilterBuilder, Expc>;

class FilterBuilderTest : public BaseBuilderTest<FilterT>
{
};
} // namespace filterbuildtest

namespace filteroperatestest
{
using SuccessExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using FilterT = OperationT<FilterBuilder, Expc>;

class FilterOperationTest : public BaseBuilderTest<FilterT>
{
};
} // namespace filteroperatestest

namespace mapbuildtest
{
using SuccessExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using MapT = BuilderT<MapBuilder, Expc>;

class MapBuilderTest : public BaseBuilderTest<MapT>
{
};
} // namespace mapbuildtest

namespace mapoperatestest
{
using SuccessExpected = InnerExpected<json::Json, const std::shared_ptr<const MockBuildCtx>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using MapT = std::tuple<std::string, MapBuilder, std::vector<OpArg>, Expc>;

class MapOperationTest : public BaseBuilderTest<MapT>
{
};
} // namespace mapoperatestest

namespace transformbuildtest
{
using SuccessExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using TransformT = BuilderT<TransformBuilder, Expc>;

class TransformBuilderTest : public BaseBuilderTest<TransformT>
{
};
} // namespace transformbuildtest

namespace transformoperatestest
{
using SuccessExpected = InnerExpected<base::Event, const std::shared_ptr<const MockBuildCtx>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<const MockBuildCtx>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using TransformT = OperationT<TransformBuilder, Expc>;

class TransformOperationTest : public BaseBuilderTest<TransformT>
{
};
} // namespace transformoperatestest

#endif // _BUILDER_TEST_BASEBUILDERS_HPP
