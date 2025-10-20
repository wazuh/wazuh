#ifndef _COMMUNITY_ID_H
#define _COMMUNITY_ID_H

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <base/error.hpp>
namespace base::utils::CommunityId
{
/**
 * @brief Compute the Zeek Community ID v1 for a network flow.
 *
 * The function canonicalizes the 5-tuple (addresses + ports/type-code + protocol),
 * normalizes direction (lower/higher endpoint ordering), builds the v1 buffer and
 * returns the "1:<base64(SHA1(..))>" string. ICMP/ICMPv6 use a/type and b/code
 * in place of ports. IPv4 and IPv6 are both supported.
 *
 * @param saddr       Source IP address (IPv4 or IPv6 string).
 * @param daddr       Destination IP address (IPv4 or IPv6 string).
 * @param sport       Source port (for TCP/UDP/SCTP) or ICMP type (for ICMP/ICMPv6).
 * @param dport       Destination port (for TCP/UDP/SCTP) or ICMP code (for ICMP/ICMPv6).
 * @param protoIana   IANA protocol number (e.g., 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, 132=SCTP).
 * @param seed        Optional seed for the hash (default 0). A non-zero seed changes the ID.
 *
 * @return CommunityResult
 *         - On success: std::string with the Community ID, e.g. "1:To62PWNVuiriSZDHqB4YZp+VAYM=".
 *         - On failure: CommunityError variant (BuildBufferFailed, Sha1Failure, Base64Failure, Unknown).
 *
 * @note The function does not throw; failures are reported via the CommunityError variant.
 * @see https://github.com/corelight/community-id-spec
 */
base::RespOrError<std::string> getCommunityIdV1(const std::string& saddr,
                                 const std::string& daddr,
                                 int64_t sport,
                                 int64_t dport,
                                 uint8_t protoIana,
                                 uint16_t seed = 0);

} // namespace base::utils::CommunityId

#endif // _COMMUNITY_ID_H
