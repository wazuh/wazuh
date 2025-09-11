#include "builders/baseBuilders_test.hpp"
#include "builders/optransform/sca.hpp"

#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>
#include <wdb/mockWdbHandler.hpp>
#include <wdb/mockWdbManager.hpp>

using namespace builder::builders::optransform;
using namespace wazuhdb::mocks;
using namespace sockiface::mocks;

namespace
{
auto getBuilder()
{
    return [=]()
    {
        auto wdbManager = std::make_shared<MockWdbManager>();
        auto sockFactory = std::make_shared<MockSockFactory>();
        return getBuilderSCAdecoder(wdbManager, sockFactory);
    };
}

auto getBuilderExpectHandler()
{
    return [=]()
    {
        auto wdbManager = std::make_shared<MockWdbManager>();
        auto wdbHandler = std::make_shared<MockWdbHandler>();
        auto sockFactory = std::make_shared<MockSockFactory>();
        auto sockHandler = std::make_shared<MockSockHandler>();
        EXPECT_CALL(*wdbManager, connection()).WillOnce(testing::Return(wdbHandler));
        EXPECT_CALL(*sockFactory,
                    getHandler(sockiface::ISockHandler::Protocol::DATAGRAM, "/var/ossec/queue/alerts/cfgarq"))
            .WillOnce(testing::Return(sockHandler));
        return getBuilderSCAdecoder(wdbManager, sockFactory);
    };
}

template<typename... T>
auto expectCustomRef(T... refs)
{
    return [=](const BuildersMocks& mocks)
    {
        if (sizeof...(refs) > 0)
        {
            EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        }
        else
        {
            EXPECT_CALL(*mocks.ctx, validator());
        }
        for (const auto& ref : {refs...})
        {
            EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        }

        return None {};
    };
}
} // namespace

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderWithDepsTest,
    testing::Values(TransformDepsT({}, getBuilder(), FAILURE()),
                    TransformDepsT({makeRef("ref")}, getBuilder(), FAILURE()),
                    TransformDepsT({makeRef("ref"), makeRef("ref")}, getBuilderExpectHandler(), SUCCESS()),
                    TransformDepsT({makeValue(R"("value")")}, getBuilder(), FAILURE()),
                    TransformDepsT({makeValue(R"("value")"), makeValue(R"("value")")}, getBuilder(), FAILURE()),
                    TransformDepsT({makeRef("ref"), makeValue(R"("value")")}, getBuilder(), FAILURE()),
                    TransformDepsT({makeValue(R"("value")"), makeRef("ref")}, getBuilder(), FAILURE()),
                    TransformDepsT({makeRef("ref"), makeRef("ref"), makeRef("ref")}, getBuilder(), FAILURE())),
    testNameFormatter<TransformBuilderWithDepsTest>("SCA"));
} // namespace transformbuildtest
