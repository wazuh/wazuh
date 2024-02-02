#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/activeResponse.hpp"

#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>

using namespace sockiface::mocks;
using namespace sockiface;

namespace
{
auto sockFactoryMock = std::make_shared<MockSockFactory>();
auto sockHandlerMock = std::make_shared<MockSockHandler>();

auto expectSockHandler()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*sockFactoryMock, getHandler(ISockHandler::Protocol::DATAGRAM, "/var/ossec/queue/alerts/ar"))
            .WillOnce(testing::Return(sockHandlerMock));
        return None {};
    };
}

auto customRefExpected(const std::string& ref)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectArQuery(const std::string& query)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*sockHandlerMock, sendMsg(query)).WillOnce(testing::Return(successSendMsgRes()));
        return None {};
    };
}

auto expectContext()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, context());
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
        /*** Send AR ***/
        MapT({}, getOpBuilderSendAr(sockFactoryMock), FAILURE()),
        MapT({makeValue(R"("query")")}, getOpBuilderSendAr(sockFactoryMock), SUCCESS(expectSockHandler())),
        MapT({makeRef("ref")}, getOpBuilderSendAr(sockFactoryMock), SUCCESS(expectSockHandler())),
        MapT({makeRef("ref"), makeRef("ref")}, getOpBuilderSendAr(sockFactoryMock), FAILURE()),
        MapT({makeValue(R"("query")"), makeValue(R"("other")")}, getOpBuilderSendAr(sockFactoryMock), FAILURE()),
        /*** Create AR ***/
        MapT({}, CreateARBuilder, FAILURE(expectContext())),
        MapT({makeValue(R"("command")")}, CreateARBuilder, FAILURE(expectContext())),
        MapT({makeRef("command")}, CreateARBuilder, FAILURE(expectContext())),
        MapT({makeValue(R"("command")"), makeValue(R"("location")")}, CreateARBuilder, SUCCESS()),
        MapT({makeRef("command"), makeRef("location")}, CreateARBuilder, FAILURE(expectContext())),
        MapT({makeValue(R"("command")"), makeRef("location")}, CreateARBuilder, SUCCESS()),
        MapT({makeValue(R"("command")"), makeValue(R"("location")"), makeValue(R"(1)")}, CreateARBuilder, SUCCESS()),
        MapT({makeValue(R"("command")"), makeValue(R"("location")"), makeRef("timeout")}, CreateARBuilder, SUCCESS()),
        MapT({makeValue(R"("command")"), makeValue(R"("location")"), makeValue(R"(1)"), makeValue(R"([])")},
             CreateARBuilder,
             SUCCESS()),
        MapT({makeValue(R"("command")"), makeValue(R"("location")"), makeValue(R"(1)"), makeRef("extra")},
             CreateARBuilder,
             SUCCESS()),
        MapT({makeValue(R"("command")"), makeValue(R"("location")"), makeValue(R"(0)"), makeValue(R"([])")},
             CreateARBuilder,
             SUCCESS()),
        MapT({makeValue(R"(true)"), makeValue(R"("location")"), makeValue(R"(1)"), makeRef("extra")},
             CreateARBuilder,
             FAILURE()),
        MapT({makeValue(R"("command")"), makeValue(R"(1)"), makeValue(R"(1)"), makeValue(R"([])")},
             CreateARBuilder,
             FAILURE(expectContext())),
        MapT({makeValue(R"("command")"), makeValue(R"("location")"), makeValue(R"("timeout")"), makeValue(R"([])")},
             CreateARBuilder,
             FAILURE(expectContext())),
        MapT({makeValue(R"("command")"), makeValue(R"("location")"), makeValue(R"(1)"), makeValue(R"({})")},
             CreateARBuilder,
             FAILURE(expectContext()))),
    testNameFormatter<MapBuilderTest>("ActiveResponse"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** Send AR ***/
        MapT(R"({})",
             getOpBuilderSendAr(sockFactoryMock),
             {makeValue(R"("query")")},
             SUCCESS(
                 [](const BuildersMocks& mocks)
                 {
                     expectSockHandler()(mocks);
                     expectArQuery("query")(mocks);
                     return json::Json {R"(true)"};
                 })),
        MapT(R"({"ref": "query"})",
             getOpBuilderSendAr(sockFactoryMock),
             {makeRef("ref")},
             SUCCESS(
                 [](const BuildersMocks& mocks)
                 {
                     expectSockHandler()(mocks);
                     expectArQuery("query")(mocks);
                     return json::Json {R"(true)"};
                 })),
        MapT(R"({})", getOpBuilderSendAr(sockFactoryMock), {makeRef("ref")}, FAILURE(expectSockHandler())),
        MapT(R"({"ref": 1})", getOpBuilderSendAr(sockFactoryMock), {makeRef("ref")}, FAILURE(expectSockHandler())),
        MapT(R"({"ref": ""})", getOpBuilderSendAr(sockFactoryMock), {makeRef("ref")}, FAILURE(expectSockHandler())),
        MapT(R"({})", getOpBuilderSendAr(sockFactoryMock), {makeValue(R"("")")}, FAILURE(expectSockHandler())),
        MapT(R"({})",
             getOpBuilderSendAr(sockFactoryMock),
             {makeValue(R"("query")")},
             FAILURE(
                 [](const BuildersMocks& mocks)
                 {
                     expectSockHandler()(mocks);
                     EXPECT_CALL(*sockHandlerMock, sendMsg("query"))
                         .WillOnce(testing::Throw(std::runtime_error("error")));
                     return None {};
                 })),
        MapT(R"({})",
             getOpBuilderSendAr(sockFactoryMock),
             {makeValue(R"("query")")},
             FAILURE(
                 [](const BuildersMocks& mocks)
                 {
                     expectSockHandler()(mocks);
                     EXPECT_CALL(*sockHandlerMock, sendMsg("query")).WillOnce(testing::Return(socketErrorSendMsgRes()));
                     return None {};
                 })),
        /*** Create AR ***/
        // TODO: this helper is never used, check if it's needed and update the tests
        MapT(
            R"({"agent": {"id": "001"}})",
            CreateARBuilder,
            {makeValue(R"("command")"), makeValue(R"("LOCAL")"), makeValue(R"(1)"), makeValue(R"([])")},
            SUCCESS(json::Json {
                R"("(local_source) [] NRN 001 {\"version\":1,\"command\":\"command1\",\"parameters\":{\"extra_args\":[],\"alert\":{\"agent\":{\"id\":\"001\"}}},\"origin\":{\"module\":\"wazuh-engine\",\"name\":\"node01\"}}")"})),
        MapT(
            R"({})",
            CreateARBuilder,
            {makeValue(R"("command")"), makeValue(R"("ALL")"), makeValue(R"(1)"), makeValue(R"([])")},
            SUCCESS(json::Json {
                R"("(local_source) [] NNS ALL {\"version\":1,\"command\":\"command1\",\"parameters\":{\"extra_args\":[],\"alert\":{}},\"origin\":{\"module\":\"wazuh-engine\",\"name\":\"node01\"}}")"})),
        MapT(
            R"({})",
            CreateARBuilder,
            {makeValue(R"("command")"), makeValue(R"("001")"), makeValue(R"(1)"), makeValue(R"([])")},
            SUCCESS(json::Json {
                R"("(local_source) [] NNS 001 {\"version\":1,\"command\":\"command1\",\"parameters\":{\"extra_args\":[],\"alert\":{}},\"origin\":{\"module\":\"wazuh-engine\",\"name\":\"node01\"}}")"})),
        MapT(
            R"({})",
            CreateARBuilder,
            {makeValue(R"("command")"), makeValue(R"("001")"), makeValue(R"(1)"), makeValue(R"(["test-arg","2"])")},
            SUCCESS(json::Json {
                R"("(local_source) [] NNS 001 {\"version\":1,\"command\":\"command1\",\"parameters\":{\"extra_args\":[\"test-arg\",\"2\"],\"alert\":{}},\"origin\":{\"module\":\"wazuh-engine\",\"name\":\"node01\"}}")"}))

            ),
    testNameFormatter<MapOperationTest>("ActiveResponse"));
} // namespace mapoperatestest
