#include "utils/ipUtils.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <limits>

namespace utils::ip
{

namespace
{
/** Canonical IANA protocol keywords by code (0..255). */
inline constexpr std::array<std::string_view, 256> IANA_NUMBER_TO_PROTOCOL_NAME_TABLE = []
{
    std::array<std::string_view, 256> a {};
    a[0] = "hopopt";
    a[1] = "icmp";
    a[2] = "igmp";
    a[3] = "ggp";
    a[4] = "ipv4";
    a[5] = "st";
    a[6] = "tcp";
    a[7] = "cbt";
    a[8] = "egp";
    a[9] = "igp";
    a[10] = "bbn-rcc-mon";
    a[11] = "nvp-ii";
    a[12] = "pup";
    a[13] = "argus";
    a[14] = "emcon";
    a[15] = "xnet";
    a[16] = "chaos";
    a[17] = "udp";
    a[18] = "mux";
    a[19] = "dcn-meas";
    a[20] = "hmp";
    a[21] = "prm";
    a[22] = "xns-idp";
    a[23] = "trunk-1";
    a[24] = "trunk-2";
    a[25] = "leaf-1";
    a[26] = "leaf-2";
    a[27] = "rdp";
    a[28] = "irtp";
    a[29] = "iso-tp4";
    a[30] = "netblt";
    a[31] = "mfe-nsp";
    a[32] = "merit-inp";
    a[33] = "dccp";
    a[34] = "3pc";
    a[35] = "idpr";
    a[36] = "xtp";
    a[37] = "ddp";
    a[38] = "idpr-cmtp";
    a[39] = "tp++";
    a[40] = "il";
    a[41] = "ipv6";
    a[42] = "sdrp";
    a[43] = "ipv6-route";
    a[44] = "ipv6-frag";
    a[45] = "idrp";
    a[46] = "rsvp";
    a[47] = "gre";
    a[48] = "dsr";
    a[49] = "bna";
    a[50] = "esp";
    a[51] = "ah";
    a[52] = "i-nlsp";
    a[53] = "swipe";
    a[54] = "narp";
    a[55] = "min-ipv4";
    a[56] = "tlsp";
    a[57] = "skip";
    a[58] = "ipv6-icmp";
    a[59] = "ipv6-nonxt";
    a[60] = "ipv6-opts";
    a[62] = "cftp";
    a[64] = "sat-expak";
    a[65] = "kryptolan";
    a[66] = "rvd";
    a[67] = "ippc";
    a[69] = "sat-mon";
    a[70] = "visa";
    a[71] = "ipcv";
    a[72] = "cpnx";
    a[73] = "cphb";
    a[74] = "wsn";
    a[75] = "pvp";
    a[76] = "br-sat-mon";
    a[77] = "sun-nd";
    a[78] = "wb-mon";
    a[79] = "wb-expak";
    a[80] = "iso-ip";
    a[81] = "vmtp";
    a[82] = "secure-vmtp";
    a[83] = "vines";
    a[84] = "iptm";
    a[85] = "nsfnet-igp";
    a[86] = "dgp";
    a[87] = "tcf";
    a[88] = "eigrp";
    a[89] = "ospfigp";
    a[90] = "sprite-rpc";
    a[91] = "larp";
    a[92] = "mtp";
    a[93] = "ax.25";
    a[94] = "ipip";
    a[95] = "micp";
    a[96] = "scc-sp";
    a[97] = "etherip";
    a[98] = "encap";
    a[100] = "gmtp";
    a[101] = "ifmp";
    a[102] = "pnni";
    a[103] = "pim";
    a[104] = "aris";
    a[105] = "scps";
    a[106] = "qnx";
    a[107] = "a/n";
    a[108] = "ipcomp";
    a[109] = "snp";
    a[110] = "compaq-peer";
    a[111] = "ipx-in-ip";
    a[112] = "vrrp";
    a[113] = "pgm";
    a[115] = "l2tp";
    a[116] = "ddx";
    a[117] = "iatp";
    a[118] = "stp";
    a[119] = "srp";
    a[120] = "uti";
    a[121] = "smp";
    a[122] = "sm";
    a[123] = "ptp";
    a[124] = "isis-over-ipv4";
    a[125] = "fire";
    a[126] = "crtp";
    a[127] = "crudp";
    a[128] = "sscopmce";
    a[129] = "iplt";
    a[130] = "sps";
    a[131] = "pipe";
    a[132] = "sctp";
    a[133] = "fc";
    a[134] = "rsvp-e2e-ignore";
    a[135] = "mobility-header";
    a[136] = "udplite";
    a[137] = "mpls-in-ip";
    a[138] = "manet";
    a[139] = "hip";
    a[140] = "shim6";
    a[141] = "wesp";
    a[142] = "rohc";
    a[143] = "ethernet";
    a[144] = "aggfrag";
    a[145] = "nsh";
    a[146] = "homa";
    a[147] = "bit-emu";
    return a;
}();
} // namespace

uint32_t IPv4ToUInt(const std::string& ipStr)
{
    int a, b, c, d {};
    char z {}; // Character after IP
    uint32_t ipUInt = 0;

    if (sscanf(ipStr.c_str(), "%d.%d.%d.%d%c", &a, &b, &c, &d, &z) != 4)
    {
        throw std::invalid_argument("Invalid IPv4 address format");
    }
    else if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
    {
        throw std::invalid_argument("Invalid IPv4 address format");
    }

    ipUInt = a << 24;
    ipUInt |= b << 16;
    ipUInt |= c << 8;
    ipUInt |= d;

    return ipUInt;
}

// TODO: Missing unit tests fot this
uint32_t IPv4MaskUInt(const std::string& maskStr)
{

    uint32_t maskUInt = 0;

    if (maskStr.find('.') != std::string::npos)
    {
        // Thow an exception if the mask is not valid
        maskUInt = IPv4ToUInt(maskStr);
    }
    else
    {
        size_t afterMask = 0;
        // Thow an `invalid_argument` exception if the mask is not a number
        auto intMask = std::stoi(maskStr, &afterMask);
        if (intMask < 0 || intMask > 32)
        {
            throw std::invalid_argument("Invalid IPv4 mask format");
        }

        if (afterMask != maskStr.size())
        {
            throw std::invalid_argument("Invalid IPv4 mask format");
        }

        maskUInt = intMask == 0 ? 0 : 0xFFFFFFFF << (32 - intMask);
    }

    return maskUInt;
}

bool checkStrIsIPv4(const std::string& ip, std::array<uint8_t, 4>* outBytes)
{
    struct in_addr buf {0};
    if (inet_pton(AF_INET, ip.c_str(), &buf) != 1)
        return false;

    if (outBytes)
        std::memcpy(outBytes->data(), &buf, outBytes->size());

    return true;
}

bool checkStrIsIPv6(const std::string& ip, std::array<uint8_t, 16>* outBytes)
{
    struct in6_addr buf {0};
    if (inet_pton(AF_INET6, ip.c_str(), &buf) != 1)
        return false;

    if (outBytes)
        std::memcpy(outBytes->data(), &buf, outBytes->size());

    return true;
}

bool isSpecialIPv4Address(const std::string& ip)
{
    uint32_t ipUInt = IPv4ToUInt(ip);

    if ((ipUInt >= 0x0A000000 && ipUInt <= 0x0AFFFFFF)     // 10.x.x.x range
        || (ipUInt >= 0xAC100000 && ipUInt <= 0xAC1FFFFF)  // 172.16.x.x to 172.31.x.x
        || (ipUInt >= 0xC0A80000 && ipUInt <= 0xC0A8FFFF)  // 192.168.x.x range
        || (ipUInt >= 0x7F000000 && ipUInt <= 0x7FFFFFFF)) // 127.x.x.x loopback range

    {
        return true;
    }
    return false;
}

bool isSpecialIPv6Address(const std::string& ip)
{
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1)
    {
        throw std::invalid_argument("Invalid IPv6 address");
    }

    return IN6_IS_ADDR_LOOPBACK(&addr)                              // Loopback
           || IN6_IS_ADDR_LINKLOCAL(&addr)                          // Link-local fe80::/10
           || (addr.s6_addr[0] == 0xFC || addr.s6_addr[0] == 0xFD); // ULA fc00::/7
}

const std::unordered_map<std::string_view, uint8_t>& IANA_PROTOCOL_NAME_TO_NUMBER()
{
    static const std::unordered_map<std::string_view, uint8_t> map = []
    {
        // Keep the cast to uint8_t safe if someone ever changes the table size.
        static_assert(IANA_NUMBER_TO_PROTOCOL_NAME_TABLE.size() <= (std::numeric_limits<uint8_t>::max() + 1u),
                      "IANA table size exceeds uint8_t range (0..255)");

        std::unordered_map<std::string_view, uint8_t> m;

        // Reserve precisely the number of non-empty entries.
        const auto nonEmpty = std::count_if(IANA_NUMBER_TO_PROTOCOL_NAME_TABLE.begin(),
                                            IANA_NUMBER_TO_PROTOCOL_NAME_TABLE.end(),
                                            [](std::string_view s) { return !s.empty(); });
        m.reserve(nonEmpty);

        // Use the container’s index type to avoid width/sign warnings.
        using index_t = decltype(IANA_NUMBER_TO_PROTOCOL_NAME_TABLE.size());
        for (index_t i = 0; i < IANA_NUMBER_TO_PROTOCOL_NAME_TABLE.size(); ++i)
        {
            std::string_view name = IANA_NUMBER_TO_PROTOCOL_NAME_TABLE[i];
            if (!name.empty())
                m.emplace(name, static_cast<uint8_t>(i));
        }
        return m;
    }();
    return map;
}

std::string normalizeIanaProtocolName(std::string_view in)
{
    std::string s(in);
    std::transform(s.begin(),
                   s.end(),
                   s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
    for (char& c : s)
        if (c == '_' || std::isspace(static_cast<unsigned char>(c)))
            c = '-';
    // aliases -> canonical keys used in the table
    if (s == "icmpv6")
        s = "ipv6-icmp";
    if (s == "udp-lite")
        s = "udplite";
    if (s == "ip-in-ip")
        s = "ipip";
    return s;
}

std::optional<uint8_t> ianaProtocolNameToNumber(std::string_view name)
{
    const std::string key = normalizeIanaProtocolName(name);
    const auto& m = IANA_PROTOCOL_NAME_TO_NUMBER();
    if (auto it = m.find(key); it != m.end())
        return it->second;
    return std::nullopt;
}

std::optional<std::string_view> ianaProtocolNumberToName(uint8_t code)
{
    std::string_view s = IANA_NUMBER_TO_PROTOCOL_NAME_TABLE[code];
    if (s.empty())
        return std::nullopt;
    return s;
}

} // namespace utils::ip
