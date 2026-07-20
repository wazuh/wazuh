#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/format.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "error.hpp"

#include "utils/communityId.hpp"
#include "utils/ipUtils.hpp"

namespace
{
inline constexpr std::size_t SEED_LEN = 2;
inline constexpr std::size_t PROTO_LEN = 1;
inline constexpr std::size_t PAD_LEN = 1;
inline constexpr std::size_t PORT_LEN = 2;
inline constexpr std::string_view CID_V1_PREFIX = "1:";
inline constexpr std::uint8_t CID_PADDING = 0;
inline constexpr std::int64_t ICMP_PORT_MAX = std::numeric_limits<std::uint8_t>::max();       // 255
inline constexpr std::int64_t TRANSPORT_PORT_MAX = std::numeric_limits<std::uint16_t>::max(); // 65535

using Sha1Digest = std::array<unsigned char, SHA_DIGEST_LENGTH>;
using ByteView = std::basic_string_view<std::uint8_t>;

enum class NetworkProto : std::uint8_t
{
    TCP = 6,
    UDP = 17,
    SCTP = 132,
    ICMP = 1,
    ICMPv6 = 58,
    OTHER = 0
};

NetworkProto toNetworkProto(std::uint8_t protocol) noexcept
{
    switch (protocol)
    {
        case 6: return NetworkProto::TCP;
        case 17: return NetworkProto::UDP;
        case 132: return NetworkProto::SCTP;
        case 1: return NetworkProto::ICMP;
        case 58: return NetworkProto::ICMPv6;
        default: return NetworkProto::OTHER;
    }
}
class NetworkEndpoint
{
public:
    enum class IpFamily : std::uint8_t
    {
        IPv4 = 4,
        IPv6 = 6,
        Unknown = 0
    };

    NetworkEndpoint(std::string_view ip, std::uint16_t port);

    ByteView getIpBytes() const noexcept;
    std::uint16_t getPort() const noexcept;
    IpFamily getFamily() const noexcept;

    friend bool operator<(const NetworkEndpoint& lhs, const NetworkEndpoint& rhs) noexcept;

private:
    void ParseIpAddress(std::string_view ip);

    std::string m_ip;
    std::uint16_t m_port {0};
    IpFamily m_family {IpFamily::Unknown};
    std::array<std::uint8_t, 16> m_ipBytes {};
    std::size_t m_len {0};
};

NetworkEndpoint::NetworkEndpoint(std::string_view ip, std::uint16_t port)
    : m_port(port)
{
    ParseIpAddress(ip);
}

ByteView NetworkEndpoint::getIpBytes() const noexcept
{
    return {m_ipBytes.data(), m_len};
}

std::uint16_t NetworkEndpoint::getPort() const noexcept
{
    return m_port;
}
NetworkEndpoint::IpFamily NetworkEndpoint::getFamily() const noexcept
{
    return m_family;
}

void NetworkEndpoint::ParseIpAddress(std::string_view ip)
{
    if (ip.empty())
        throw std::invalid_argument("IP address is empty");

    m_ip.assign(ip);
    std::array<std::uint8_t, 4> tmp4 {};

    if (utils::ip::checkStrIsIPv4(m_ip, &tmp4))
    {
        std::memcpy(m_ipBytes.data(), tmp4.data(), tmp4.size());
        m_family = IpFamily::IPv4;
        m_len = 4;
    }
    else if (utils::ip::checkStrIsIPv6(m_ip, &m_ipBytes))
    {
        m_family = IpFamily::IPv6;
        m_len = 16;
    }
    else
    {
        throw std::invalid_argument("Invalid IP address format: " + m_ip);
    }
}

bool operator<(const NetworkEndpoint& lhs, const NetworkEndpoint& rhs) noexcept
{
    const auto lb = lhs.getIpBytes();
    const auto rb = rhs.getIpBytes();

    if (!std::equal(lb.begin(), lb.end(), rb.begin()))
        return std::lexicographical_compare(lb.begin(), lb.end(), rb.begin(), rb.end());

    if (lhs.getPort() != rhs.getPort())
        return lhs.getPort() < rhs.getPort();

    return false;
}

struct CommunityTupleArgs
{
    NetworkEndpoint src;
    NetworkEndpoint dst;
    std::uint8_t protoIana;
    std::uint16_t seed;
};

std::optional<Sha1Digest> computeSha1Digest(std::string_view data)
{
    Sha1Digest out {};
    unsigned char* ok =
        ::SHA1(reinterpret_cast<const unsigned char*>(data.data()), static_cast<size_t>(data.size()), out.data());
    if (!ok)
        return std::nullopt;
    return out;
}

std::optional<std::string> encodeDigestToBase64(const Sha1Digest& digest)
{
    constexpr int SHA1_BASE64_LEN = 28;

    std::string result(SHA1_BASE64_LEN, '\0');

    int written =
        ::EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&result[0]), digest.data(), static_cast<int>(digest.size()));
    if (written <= 0)
        return std::nullopt;

    result.resize(written);

    return result;
}

std::optional<std::string> buildCidBuffer(const CommunityTupleArgs& tupleArgs)
{
    const auto ip1 = tupleArgs.src.getIpBytes();
    const auto ip2 = tupleArgs.dst.getIpBytes();

    const std::size_t total = SEED_LEN + ip1.size() + ip2.size() + PROTO_LEN + PAD_LEN + PORT_LEN + PORT_LEN;

    std::string buffer(total, '\0');
    std::size_t offset = 0;

    auto put_u8 = [&](std::uint8_t value8)
    {
        buffer[offset++] = static_cast<char>(value8);
    };

    auto put_u16b = [&](std::uint16_t value16)
    {
        buffer[offset++] = static_cast<char>((value16 >> 8) & 0xFF);
        buffer[offset++] = static_cast<char>(value16 & 0xFF);
    };

    auto put_span = [&](ByteView ipBytes)
    {
        std::memcpy(&buffer[offset], ipBytes.data(), ipBytes.size());
        offset += ipBytes.size();
    };

    // Orden Community ID v1:
    // seed(2) | ip1(4/16) | ip2(4/16) | proto(1) | pad(1) | sport(2) | dport(2)
    put_u16b(tupleArgs.seed);
    put_span(ip1);
    put_span(ip2);
    put_u8(tupleArgs.protoIana);
    put_u8(CID_PADDING); // padding fijo
    put_u16b(tupleArgs.src.getPort());
    put_u16b(tupleArgs.dst.getPort());

    if (offset != total)
        return std::nullopt;

    return buffer;
}

bool validatePortsForProto(std::uint8_t protoIana, std::int64_t sport, std::int64_t dport, std::string& outErr) noexcept
{
    const auto proto = toNetworkProto(protoIana);

    if (proto == NetworkProto::ICMP || proto == NetworkProto::ICMPv6)
    {
        if (sport < 0 || sport > ICMP_PORT_MAX)
        {
            outErr = "source.port out of range (expected 0..255)";
            return false;
        }
        if (dport < 0 || dport > ICMP_PORT_MAX)
        {
            outErr = "destination.port out of range (expected 0..255)";
            return false;
        }
        return true;
    }

    if (proto == NetworkProto::TCP || proto == NetworkProto::UDP || proto == NetworkProto::SCTP)
    {
        if (sport <= 0 || sport > TRANSPORT_PORT_MAX)
        {
            outErr = "source.port out of range (expected 1..65535)";
            return false;
        }

        if (dport <= 0 || dport > TRANSPORT_PORT_MAX)
        {
            outErr = "destination.port out of range (expected 1..65535)";
            return false;
        }

        return true;
    }

    // Other protocols do not use ports, but we allow 0 values for compatibility
    if (sport < 0 || sport > TRANSPORT_PORT_MAX)
    {
        outErr = "source.port out of range (expected 0..65535)";
        return false;
    }
    if (dport < 0 || dport > TRANSPORT_PORT_MAX)
    {
        outErr = "destination.port out of range (expected 0..65535)";
        return false;
    }

    return true;
}

base::RespOrError<std::string> buildCommunityId(const CommunityTupleArgs& args)
{
    auto buffer = buildCidBuffer(args);
    if (!buffer)
        return base::Error {"Failed to build Community ID buffer"};

    auto digest = computeSha1Digest(*buffer);
    if (!digest)
        return base::Error {"Failed to compute SHA1 digest"};

    auto b64 = encodeDigestToBase64(*digest);
    if (!b64)
        return base::Error {"Failed to encode SHA1 digest to Base64"};

    std::string out;
    out.reserve(CID_V1_PREFIX.size() + b64->size());
    out.append(CID_V1_PREFIX.data(), CID_V1_PREFIX.size());
    out.append(*b64);
    return out;
}

} // namespace

namespace base::utils::CommunityId
{
base::RespOrError<std::string> getCommunityIdV1(
    const std::string& saddr, const std::string& daddr, int64_t sport, int64_t dport, uint8_t protoIana, uint16_t seed)
{
    try
    {
        std::string portErr;
        if (!validatePortsForProto(protoIana, sport, dport, portErr))
        {
            return base::Error {portErr};
        }

        NetworkEndpoint src(saddr, static_cast<std::uint16_t>(sport));
        NetworkEndpoint dst(daddr, static_cast<std::uint16_t>(dport));

        if (src.getFamily() != dst.getFamily())
        {
            return base::Error{"Algorithm requires both IPs to be of the same family (IPv4 or IPv6)"};
        }

        if (dst < src)
            std::swap(src, dst);

        CommunityTupleArgs args {std::move(src), std::move(dst), protoIana, seed};
        return buildCommunityId(args);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to compute Community ID '{}'", e.what())};
    }
}

} // namespace base::utils::CommunityId
