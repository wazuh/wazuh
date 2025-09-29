#include <gtest/gtest.h>

#include <base/utils/communityId.hpp>

#include <variant>

namespace
{
using base::utils::CommunityId::CommunityError;
using base::utils::CommunityId::CommunityResult;
using base::utils::CommunityId::getCommunityIdV1;

void expectStringResult(const CommunityResult& result, const std::string& expected)
{
    ASSERT_TRUE(std::holds_alternative<std::string>(result)) << "Expected Community ID string but got error";
    EXPECT_EQ(expected, std::get<std::string>(result));
}

} // namespace

TEST(CommunityIdTest, TcpIpv4ReturnsExpected)
{
    const auto result = getCommunityIdV1("192.168.0.1", "10.0.0.5", 12345, 80, 6);
    expectStringResult(result, "1:JHvDxB6S6/K68OntUBf4DJZYvkM=");
}

TEST(CommunityIdTest, CanonicalizesEndpointOrdering)
{
    const auto forward = getCommunityIdV1("192.168.0.1", "10.0.0.5", 12345, 80, 6);
    const auto swapped = getCommunityIdV1("10.0.0.5", "192.168.0.1", 80, 12345, 6);

    ASSERT_TRUE(std::holds_alternative<std::string>(forward));
    ASSERT_TRUE(std::holds_alternative<std::string>(swapped));
    EXPECT_EQ(std::get<std::string>(forward), std::get<std::string>(swapped));
}

TEST(CommunityIdTest, Ipv6EncapsulationFlow)
{
    const auto result = getCommunityIdV1("2001:db8::1", "2001:db8::2", 0, 0, 41);
    expectStringResult(result, "1:CXfAfp/8zYUwm/5DkEbJvPdJtcU=");
}

TEST(CommunityIdTest, IcmpFlowUsesTypeAndCode)
{
    const auto result = getCommunityIdV1("192.0.2.1", "198.51.100.2", 8, 0, 1);
    expectStringResult(result, "1:zFLKq9oekfjLhmre/zOf0XYYjVE=");
}

TEST(CommunityIdTest, InvalidIpReturnsUnknownError)
{
    const auto result = getCommunityIdV1("not-an-ip", "10.0.0.5", 12345, 80, 6);

    ASSERT_TRUE(std::holds_alternative<CommunityError>(result)) << "Expected error variant but got Community ID string";
    EXPECT_EQ(CommunityError::Unknown, std::get<CommunityError>(result));
}
