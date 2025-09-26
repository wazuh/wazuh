#ifndef _COMMUNITY_ID_H
#define _COMMUNITY_ID_H

#include <cstdint>
#include <optional>
#include <string>
#include <variant>

namespace base::utils::CommunityId
{
    enum class CommunityError : std::uint8_t
    {
        BuildBufferFailed,
        Sha1Failure,
        Base64Failure,
        Unknown
    };

    using CommunityResult = std::variant<std::string, CommunityError>;

    /**
    * @brief someething
    *
    * @param str something
    * @return something
    */
    CommunityResult getCommunityIdV1( const std::string& saddr, const std::string& daddr, uint16_t sport, uint16_t dport, uint8_t protoIana, uint16_t seed = 0 );


} // namespace utils::CommunityId

#endif // _COMMUNITY_ID_H