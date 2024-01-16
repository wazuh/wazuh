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

struct Mocks
{
    std::shared_ptr<const MockBuildCtx> ctx;
    std::shared_ptr<const RunState> runState;
    std::shared_ptr<MockSchema> schema;
    std::shared_ptr<MockValidator> validator;
    Context context;
};

template<typename T>
class BaseBuilderTest : public testing::TestWithParam<T>
{
protected:
    std::shared_ptr<Mocks> mocks;

    void SetUp() override
    {
        mocks = std::make_shared<Mocks>();
        mocks->ctx = std::make_shared<const MockBuildCtx>();
        mocks->runState = std::make_shared<const RunState>();
        mocks->schema = std::make_shared<MockSchema>();
        mocks->validator = std::make_shared<MockValidator>();

        ON_CALL(*mocks->ctx, context()).WillByDefault(testing::ReturnRef(mocks->context));
        ON_CALL(*mocks->ctx, runState()).WillByDefault(testing::Return(mocks->runState));
        ON_CALL(*mocks->ctx, schema()).WillByDefault(testing::ReturnRef(*(mocks->schema)));
        ON_CALL(*mocks->ctx, validator()).WillByDefault(testing::ReturnRef(*(mocks->validator)));
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

inline auto ctxExpected()
{
    return [](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, context());
        return None {};
    };
}

namespace filterbuildtest
{
using SuccessExpected = InnerExpected<None, const Mocks&>;
using FailureExpected = InnerExpected<None, const Mocks&>;
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
using SuccessExpected = InnerExpected<None, const Mocks&>;
using FailureExpected = InnerExpected<None, const Mocks&>;
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
using SuccessExpected = InnerExpected<None, const Mocks&>;
using FailureExpected = InnerExpected<None, const Mocks&>;
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
using SuccessExpected = InnerExpected<json::Json, const Mocks&>;
using FailureExpected = InnerExpected<None, const Mocks&>;
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
using SuccessExpected = InnerExpected<None, const Mocks&>;
using FailureExpected = InnerExpected<None, const Mocks&>;
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
using SuccessExpected = InnerExpected<base::Event, const Mocks&>;
using FailureExpected = InnerExpected<None, const Mocks&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
static auto SUCCESS = Expc::success();
static auto FAILURE = Expc::failure();

using TransformT = OperationT<TransformBuilder, Expc>;

class TransformOperationTest : public BaseBuilderTest<TransformT>
{
};
} // namespace transformoperatestest

#endif // _BUILDER_TEST_BASEBUILDERS_HPP
