#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/activeResponse.hpp"

#include <sockiface/mockSockFactory.hpp>
#include <sockiface/mockSockHandler.hpp>

using namespace sockiface::mocks;
using namespace sockiface;

namespace
{

mapbuildtest::BuilderGetter getBuilder()
{
    return []()
    {
        auto sockFactoryMock = std::make_shared<MockSockFactory>();
        return getOpBuilderSendAr(sockFactoryMock);
    };
}

mapbuildtest::BuilderGetter getBuilderExpectSockHandler()
{
    return []()
    {
        auto sockFactoryMock = std::make_shared<MockSockFactory>();
        auto sockHandlerMock = std::make_shared<MockSockHandler>();
        EXPECT_CALL(*sockFactoryMock, getHandler(ISockHandler::Protocol::DATAGRAM, "/var/ossec/queue/alerts/ar"))
            .WillOnce(testing::Return(sockHandlerMock));
        return getOpBuilderSendAr(sockFactoryMock);
    };
}

template<typename Behaviour>
mapbuildtest::BuilderGetter getBuilderExpectSockHandler(Behaviour&& behaviour)
{
    return [=]()
    {
        auto sockFactoryMock = std::make_shared<MockSockFactory>();
        auto sockHandlerMock = std::make_shared<MockSockHandler>();
        EXPECT_CALL(*sockFactoryMock, getHandler(ISockHandler::Protocol::DATAGRAM, "/var/ossec/queue/alerts/ar"))
            .WillOnce(testing::Return(sockHandlerMock));
        behaviour(sockHandlerMock);
        return getOpBuilderSendAr(sockFactoryMock);
    };
}

auto customRefExpected(const std::string& ref)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
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
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapBuilderWithDepsTest,
                         testing::Values(
                             /*** Send AR ***/
                             MapDepsT({}, getBuilder(), FAILURE()),
                             MapDepsT({makeValue(R"("query")")}, getBuilderExpectSockHandler(), SUCCESS()),
                             MapDepsT({makeRef("ref")}, getBuilderExpectSockHandler(), SUCCESS()),
                             MapDepsT({makeRef("ref"), makeRef("ref")}, getBuilder(), FAILURE()),
                             MapDepsT({makeValue(R"("query")"), makeValue(R"("other")")}, getBuilder(), FAILURE())),
                         testNameFormatter<MapBuilderWithDepsTest>("ActiveResponse"));

INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderTest,
    testing::Values(
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
                R"("(local_source) [] NNS 001 {\"version\":1,\"command\":\"command1\",\"parameters\":{\"extra_args\":[\"test-arg\",\"2\"],\"alert\":{}},\"origin\":{\"module\":\"wazuh-engine\",\"name\":\"node01\"}}")"}))),
    testNameFormatter<MapOperationTest>("ActiveResponse"));

INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationWithDepsTest,
    testing::Values(
        /*** Send AR ***/
        MapDepsT(R"({})",
                 getBuilderExpectSockHandler(
                     [](const std::shared_ptr<MockSockHandler>& handler)
                     { EXPECT_CALL(*handler, sendMsg("query")).WillOnce(testing::Return(successSendMsgRes())); }),
                 {makeValue(R"("query")")},
                 SUCCESS(json::Json {R"(true)"})),
        MapDepsT(R"({"ref": "query"})",
                 getBuilderExpectSockHandler(
                     [](const std::shared_ptr<MockSockHandler>& handler)
                     { EXPECT_CALL(*handler, sendMsg("query")).WillOnce(testing::Return(successSendMsgRes())); }),
                 {makeRef("ref")},
                 SUCCESS(json::Json {R"(true)"})),
        MapDepsT(R"({})", getBuilderExpectSockHandler(), {makeRef("ref")}, FAILURE()),
        MapDepsT(R"({"ref": 1})", getBuilderExpectSockHandler(), {makeRef("ref")}, FAILURE()),
        MapDepsT(R"({"ref": ""})", getBuilderExpectSockHandler(), {makeRef("ref")}, FAILURE()),
        MapDepsT(R"({})", getBuilderExpectSockHandler(), {makeValue(R"("")")}, FAILURE()),
        MapDepsT(R"({})",
                 getBuilderExpectSockHandler(
                     [](const std::shared_ptr<MockSockHandler>& handler) {
                         EXPECT_CALL(*handler, sendMsg("query")).WillOnce(testing::Throw(std::runtime_error("error")));
                     }),
                 {makeValue(R"("query")")},
                 FAILURE()),
        MapDepsT(R"({})",
                 getBuilderExpectSockHandler(
                     [](const std::shared_ptr<MockSockHandler>& handler)
                     { EXPECT_CALL(*handler, sendMsg("query")).WillOnce(testing::Return(socketErrorSendMsgRes())); }),
                 {makeValue(R"("query")")},
                 FAILURE())),
    testNameFormatter<MapOperationWithDepsTest>("ActiveResponse"));
} // namespace mapoperatestest
