#include "builders/baseBuilders_test.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"

#include <base/utils/communityId.hpp>

#include <fmt/format.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include <gmock/gmock.h>

using namespace builder::builders;

namespace
{
std::vector<OpArg> makeDefaultArgs()
{
    return {makeRef("source.ip"),
            makeRef("destination.ip"),
            makeRef("source.port"),
            makeRef("destination.port"),
            makeRef("network.iana_number")};
}

std::vector<OpArg> makeProtoLiteralArgs(uint8_t proto)
{
    auto args = makeDefaultArgs();
    args[4] = makeValue(std::to_string(proto));
    return args;
}

json::Json
successCidForFlow(const std::string& saddr, const std::string& daddr, uint16_t sport, uint16_t dport, uint8_t proto)
{
    auto result = base::utils::CommunityId::getCommunityIdV1(saddr, daddr, sport, dport, proto, 0);
    if (base::isError(result))
    {
        throw std::runtime_error(
            fmt::format("Failed to compute community ID for test expectation: {}", base::getError(result).message));
    }

    const auto encoded = fmt::format("\"{}\"", base::getResponse(result));
    return json::Json(encoded.c_str());
}

void expectSchemaAbsentLookups(const BuildersMocks& mocks)
{
    EXPECT_CALL(*mocks.ctx, validator())
        .Times(testing::AnyNumber())
        .WillRepeatedly(testing::ReturnRef(*mocks.validator));
    EXPECT_CALL(*mocks.validator, hasField(testing::_))
        .Times(testing::AnyNumber())
        .WillRepeatedly(testing::Return(false));
}
} // namespace

namespace mapbuildtest
{
auto builderExpectation()
{
    return [](const BuildersMocks& mocks)
    {
        expectSchemaAbsentLookups(mocks);
        return base::test::None {};
    };
}

auto builderSuccess()
{
    return SuccessExpected::Param {SuccessExpected::Behaviour(builderExpectation())};
}

auto builderFailure()
{
    return FailureExpected::Param {FailureExpected::Behaviour(builderExpectation())};
}

INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderTest,
    testing::Values(
        MapT({}, opBuilderHelperNetworkCommunityId, FAILURE(builderFailure())),
        MapT({makeRef("source.ip"), makeRef("destination.ip"), makeRef("source.port"), makeRef("destination.port")},
             opBuilderHelperNetworkCommunityId,
             FAILURE(builderFailure())),
        MapT(
            []()
            {
                auto args = makeDefaultArgs();
                args.emplace_back(makeValue("0"));
                return args;
            }(),
            opBuilderHelperNetworkCommunityId,
            FAILURE(builderFailure())),
        MapT({makeRef("source.ip"),
              makeRef("destination.ip"),
              makeRef("source.port"),
              makeRef("destination.port"),
              makeRef("network.iana_number"),
              makeValue("0")},
             opBuilderHelperNetworkCommunityId,
             FAILURE(builderFailure())),
        MapT(
            []()
            {
                auto args = makeDefaultArgs();
                args[0] = makeValue(R"("192.0.2.1")");
                return args;
            }(),
            opBuilderHelperNetworkCommunityId,
            FAILURE(builderFailure())),
        MapT(
            []()
            {
                auto args = makeDefaultArgs();
                args[4] = makeValue(R"("proto")");
                return args;
            }(),
            opBuilderHelperNetworkCommunityId,
            FAILURE(builderFailure())),
        MapT(
            []()
            {
                auto args = makeDefaultArgs();
                args[4] = makeValue("300");
                return args;
            }(),
            opBuilderHelperNetworkCommunityId,
            FAILURE(builderFailure())),
        MapT(makeDefaultArgs(), opBuilderHelperNetworkCommunityId, SUCCESS(builderSuccess())),
        MapT(makeProtoLiteralArgs(17), opBuilderHelperNetworkCommunityId, SUCCESS(builderSuccess()))),
    testNameFormatter<MapBuilderTest>("NetworkCommunityId"));
} // namespace mapbuildtest

namespace mapoperatestest
{
auto operationSuccess(json::Json expected)
{
    return SuccessExpected::Param {SuccessExpected::Behaviour(
        [expected = std::move(expected)](const BuildersMocks& mocks) mutable
        {
            expectSchemaAbsentLookups(mocks);
            return expected;
        })};
}

auto operationFailure()
{
    return FailureExpected::Param {FailureExpected::Behaviour(
        [](const BuildersMocks& mocks)
        {
            expectSchemaAbsentLookups(mocks);
            return base::test::None {};
        })};
}

INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        // Success cases
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            SUCCESS(operationSuccess(successCidForFlow("192.168.0.1", "10.0.0.5", 12345, 80, 6)))),
        MapT(R"({"source":{"ip":"10.1.1.1","port":5353},"destination":{"ip":"10.1.1.2","port":53}})",
             opBuilderHelperNetworkCommunityId,
             makeProtoLiteralArgs(17),
             SUCCESS(operationSuccess(successCidForFlow("10.1.1.1", "10.1.1.2", 5353, 53, 17)))),
        MapT(R"({"source":{"ip":"2001:db8::1"},"destination":{"ip":"2001:db8::2"},"network":{"iana_number":41}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             SUCCESS(operationSuccess(successCidForFlow("2001:db8::1", "2001:db8::2", 0, 0, 41)))),
        MapT(
            R"({"source":{"ip":"192.0.2.1","port":8},"destination":{"ip":"198.51.100.2","port":0},"network":{"iana_number":1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            SUCCESS(operationSuccess(successCidForFlow("192.0.2.1", "198.51.100.2", 8, 0, 1)))),
        // Failure cases
        MapT(R"({"source":{"port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":12345,"port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"not-an-ip","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"port":80},"network":{"iana_number":6}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"2001:db8::1","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":80,"port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"300.0.0.1","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":"six"}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":-1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":300}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(R"({"source":{"ip":"192.168.0.1"},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":"12345"},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5"},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":70000},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.0.2.1","port":300},"destination":{"ip":"198.51.100.2","port":0},"network":{"iana_number":1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure())),
        MapT(
            R"({"source":{"ip":"192.0.2.1","port":8},"destination":{"ip":"198.51.100.2","port":"0"},"network":{"iana_number":1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE(operationFailure()))),
    testNameFormatter<MapOperationTest>("NetworkCommunityId"));
} // namespace mapoperatestest
