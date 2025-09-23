#ifndef _COMMUNITY_ID_H
#define _COMMUNITY_ID_H

#include <cstdint>
#include <optional>
#include <string>

namespace base::utils::CommunityId
{
    /**
    * @brief someething
    *
    * @param str something
    * @return something
    */
    std::string getCommunityIdV1( const std::string& saddr, const std::string& daddr, uint16_t sport, int16_t dport, uint8_t protoIana, uint16_t seed = 0 );


} // namespace utils::CommunityId

#endif // _COMMUNITY_ID_H