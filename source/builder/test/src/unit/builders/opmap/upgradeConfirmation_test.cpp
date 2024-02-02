#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/upgradeConfirmation.hpp"

#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>

using namespace sockiface::mocks;
using namespace sockiface;
using namespace builder::builders::opmap;

namespace
{
auto sockFactoryMock = std::make_shared<MockSockFactory>();
auto sockHandlerMock = std::make_shared<MockSockHandler>();

auto expectSockHandler()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*sockFactoryMock, getHandler(ISockHandler::Protocol::STREAM, WM_UPGRADE_SOCK))
            .WillOnce(testing::Return(sockHandlerMock));
        return None {};
    };
}
} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderTest,
    testing::Values(
        MapT({}, getUpgradeConfirmationBUilder(sockFactoryMock), FAILURE()),
        MapT({makeValue(R"("value")")}, getUpgradeConfirmationBUilder(sockFactoryMock), FAILURE()),
        MapT({makeRef("ref")}, getUpgradeConfirmationBUilder(sockFactoryMock), SUCCESS(expectSockHandler())),
        MapT({makeRef("ref"), makeValue(R"("other")")}, getUpgradeConfirmationBUilder(sockFactoryMock), FAILURE())),
    testNameFormatter<MapBuilderTest>("UpgradeConfirmation"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapOperationTest,
                         testing::Values(MapT(R"({"ref": {"some":"data"}})",
                                              getUpgradeConfirmationBUilder(sockFactoryMock),
                                              {makeRef("ref")},
                                              SUCCESS(
                                                  [](const BuildersMocks& mocks)
                                                  {
                                                      expectSockHandler()(mocks);
                                                      EXPECT_CALL(*sockHandlerMock, sendMsg(R"({"some":"data"})"))
                                                          .WillOnce(testing::Return(successSendMsgRes()));
                                                      return json::Json("true");
                                                  })),
                                         MapT(R"({})",
                                              getUpgradeConfirmationBUilder(sockFactoryMock),
                                              {makeRef("ref")},
                                              FAILURE(expectSockHandler())),
                                         MapT(R"({"ref": "notObject"})",
                                              getUpgradeConfirmationBUilder(sockFactoryMock),
                                              {makeRef("ref")},
                                              FAILURE(expectSockHandler())),
                                         MapT(R"({"ref":{}})",
                                              getUpgradeConfirmationBUilder(sockFactoryMock),
                                              {makeRef("ref")},
                                              FAILURE(expectSockHandler())),
                                         MapT(R"({"ref": {"some":"data"}})",
                                              getUpgradeConfirmationBUilder(sockFactoryMock),
                                              {makeRef("ref")},
                                              FAILURE(
                                                  [](const BuildersMocks& mocks)
                                                  {
                                                      expectSockHandler()(mocks);
                                                      EXPECT_CALL(*sockHandlerMock, sendMsg(R"({"some":"data"})"))
                                                          .WillOnce(testing::Return(socketErrorSendMsgRes()));
                                                      return None {};
                                                  })),
                                         MapT(R"({"ref": {"some":"data"}})",
                                              getUpgradeConfirmationBUilder(sockFactoryMock),
                                              {makeRef("ref")},
                                              FAILURE(
                                                  [](const BuildersMocks& mocks)
                                                  {
                                                      expectSockHandler()(mocks);
                                                      EXPECT_CALL(*sockHandlerMock, sendMsg(R"({"some":"data"})"))
                                                          .WillOnce(testing::Throw(std::runtime_error("error")));
                                                      return None {};
                                                  }))),
                         testNameFormatter<MapOperationTest>("UpgradeConfirmation"));
} // namespace mapoperatestest
