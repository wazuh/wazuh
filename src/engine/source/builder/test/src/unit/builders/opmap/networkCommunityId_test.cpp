#include "builders/baseBuilders_test.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"

#include <base/utils/communityId.hpp>

#include <fmt/format.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

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

std::vector<OpArg> makeArgsWithSeed(const std::string& seedJson)
{
    auto args = makeDefaultArgs();
    args.emplace_back(makeValue(seedJson));
    return args;
}

auto successCidForFlow(const std::string& saddr,
                       const std::string& daddr,
                       uint16_t sport,
                       uint16_t dport,
                       uint8_t proto,
                       uint16_t seed = 0)
{
    return [=](const BuildersMocks&)
    {
        auto result = base::utils::CommunityId::getCommunityIdV1(saddr, daddr, sport, dport, proto, seed);
        if (!std::holds_alternative<std::string>(result))
        {
            throw std::runtime_error("Failed to compute community ID for test expectation");
        }
        return json::Json(fmt::format("\"{}\"", std::get<std::string>(result)));
    };
}
} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderTest,
    testing::Values(
        MapT({}, opBuilderHelperNetworkCommunityId, FAILURE()),
        MapT({makeRef("source.ip"), makeRef("destination.ip"), makeRef("source.port"), makeRef("destination.port")},
             opBuilderHelperNetworkCommunityId,
             FAILURE()),
        MapT({makeRef("source.ip"),
              makeRef("destination.ip"),
              makeRef("source.port"),
              makeRef("destination.port"),
              makeRef("network.iana_number"),
              makeValue("0"),
              makeValue("1")},
             opBuilderHelperNetworkCommunityId,
             FAILURE()),
        MapT(
            []()
            {
                auto args = makeDefaultArgs();
                args[0] = makeValue(R"("192.0.2.1")");
                return args;
            }(),
            opBuilderHelperNetworkCommunityId,
            FAILURE()),
        MapT(
            []()
            {
                auto args = makeDefaultArgs();
                args[4] = makeValue("6");
                return args;
            }(),
            opBuilderHelperNetworkCommunityId,
            FAILURE()),
        MapT(
            []()
            {
                auto args = makeDefaultArgs();
                args.emplace_back(makeRef("seed.ref"));
                return args;
            }(),
            opBuilderHelperNetworkCommunityId,
            FAILURE()),
        MapT(makeArgsWithSeed(R"("seed")"), opBuilderHelperNetworkCommunityId, FAILURE()),
        MapT(makeArgsWithSeed("-1"), opBuilderHelperNetworkCommunityId, FAILURE()),
        MapT(makeArgsWithSeed("70000"), opBuilderHelperNetworkCommunityId, FAILURE()),
        MapT(makeDefaultArgs(), opBuilderHelperNetworkCommunityId, SUCCESS()),
        MapT(makeArgsWithSeed("123"), opBuilderHelperNetworkCommunityId, SUCCESS())),
    testNameFormatter<MapBuilderTest>("NetworkCommunityId"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        // Success cases
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            SUCCESS(successCidForFlow("192.168.0.1", "10.0.0.5", 12345, 80, 6))),
        MapT(
            R"({"source":{"ip":"10.1.1.1","port":5353},"destination":{"ip":"10.1.1.2","port":53},"network":{"iana_number":17}})",
            opBuilderHelperNetworkCommunityId,
            makeArgsWithSeed("42"),
            SUCCESS(successCidForFlow("10.1.1.1", "10.1.1.2", 5353, 53, 17, 42))),
        MapT(R"({"source":{"ip":"2001:db8::1"},"destination":{"ip":"2001:db8::2"},"network":{"iana_number":41}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             SUCCESS(successCidForFlow("2001:db8::1", "2001:db8::2", 0, 0, 41))),
        MapT(
            R"({"source":{"ip":"192.0.2.1","port":8},"destination":{"ip":"198.51.100.2","port":0},"network":{"iana_number":1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            SUCCESS(successCidForFlow("192.0.2.1", "198.51.100.2", 8, 0, 1))),
        // Failure cases
        MapT(R"({"source":{"port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE()),
        MapT(
            R"({"source":{"ip":12345,"port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"not-an-ip","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"port":80},"network":{"iana_number":6}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":80,"port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"300.0.0.1","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":"six"}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":-1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":300}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(R"({"source":{"ip":"192.168.0.1"},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
             opBuilderHelperNetworkCommunityId,
             makeDefaultArgs(),
             FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":"12345"},"destination":{"ip":"10.0.0.5","port":80},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5"},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"192.168.0.1","port":12345},"destination":{"ip":"10.0.0.5","port":70000},"network":{"iana_number":6}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"192.0.2.1","port":300},"destination":{"ip":"198.51.100.2","port":0},"network":{"iana_number":1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE()),
        MapT(
            R"({"source":{"ip":"192.0.2.1","port":8},"destination":{"ip":"198.51.100.2","port":"0"},"network":{"iana_number":1}})",
            opBuilderHelperNetworkCommunityId,
            makeDefaultArgs(),
            FAILURE())),
    testNameFormatter<MapOperationTest>("NetworkCommunityId"));
} // namespace mapoperatestest
