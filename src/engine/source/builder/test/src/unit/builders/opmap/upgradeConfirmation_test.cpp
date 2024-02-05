#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/upgradeConfirmation.hpp"

#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>

using namespace sockiface::mocks;
using namespace sockiface;
using namespace builder::builders::opmap;

namespace
{

mapbuildtest::BuilderGetter getBuilder()
{
    return []()
    {
        auto sockFactoryMock = std::make_shared<MockSockFactory>();
        return getUpgradeConfirmationBUilder(sockFactoryMock);
    };
}

mapbuildtest::BuilderGetter getBuilderExpectSockHandler()
{
    return []()
    {
        auto sockFactoryMock = std::make_shared<MockSockFactory>();
        auto sockHandlerMock = std::make_shared<MockSockHandler>();
        EXPECT_CALL(*sockFactoryMock, getHandler(ISockHandler::Protocol::STREAM, WM_UPGRADE_SOCK))
            .WillOnce(testing::Return(sockHandlerMock));
        return getUpgradeConfirmationBUilder(sockFactoryMock);
    };
}

template<typename Behaviour>
mapbuildtest::BuilderGetter getBuilderExpectSockHandler(Behaviour&& behaviour)
{
    return [=]()
    {
        auto sockFactoryMock = std::make_shared<MockSockFactory>();
        auto sockHandlerMock = std::make_shared<MockSockHandler>();
        EXPECT_CALL(*sockFactoryMock, getHandler(ISockHandler::Protocol::STREAM, WM_UPGRADE_SOCK))
            .WillOnce(testing::Return(sockHandlerMock));
        behaviour(sockHandlerMock);
        return getUpgradeConfirmationBUilder(sockFactoryMock);
    };
}

} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapBuilderWithDepsTest,
                         testing::Values(MapDepsT({}, getBuilder(), FAILURE()),
                                         MapDepsT({makeValue(R"("value")")}, getBuilder(), FAILURE()),
                                         MapDepsT({makeRef("ref")}, getBuilderExpectSockHandler(), SUCCESS()),
                                         MapDepsT({makeRef("ref"), makeValue(R"("other")")}, getBuilder(), FAILURE())),
                         testNameFormatter<MapBuilderWithDepsTest>("UpgradeConfirmation"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationWithDepsTest,
    testing::Values(MapDepsT(R"({"ref": {"some":"data"}})",
                             getBuilderExpectSockHandler(
                                 [](std::shared_ptr<MockSockHandler> sockHandlerMock) {
                                     EXPECT_CALL(*sockHandlerMock, sendMsg(R"({"some":"data"})"))
                                         .WillOnce(testing::Return(successSendMsgRes()));
                                 }),
                             {makeRef("ref")},
                             SUCCESS(json::Json("true"))),
                    MapDepsT(R"({})", getBuilderExpectSockHandler(), {makeRef("ref")}, FAILURE()),
                    MapDepsT(R"({"ref": "notObject"})", getBuilderExpectSockHandler(), {makeRef("ref")}, FAILURE()),
                    MapDepsT(R"({"ref":{}})", getBuilderExpectSockHandler(), {makeRef("ref")}, FAILURE()),
                    MapDepsT(R"({"ref": {"some":"data"}})",
                             getBuilderExpectSockHandler(
                                 [](std::shared_ptr<MockSockHandler> sockHandlerMock) {
                                     EXPECT_CALL(*sockHandlerMock, sendMsg(R"({"some":"data"})"))
                                         .WillOnce(testing::Return(socketErrorSendMsgRes()));
                                 }),
                             {makeRef("ref")},
                             FAILURE()),
                    MapDepsT(R"({"ref": {"some":"data"}})",
                             getBuilderExpectSockHandler(
                                 [](std::shared_ptr<MockSockHandler> sockHandlerMock)
                                 {
                                     EXPECT_CALL(*sockHandlerMock, sendMsg(R"({"some":"data"})"))
                                         .WillOnce(testing::Throw(std::runtime_error("error")));
                                 }),
                             {makeRef("ref")},
                             FAILURE())),
    testNameFormatter<MapOperationWithDepsTest>("UpgradeConfirmation"));
} // namespace mapoperatestest
