// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _AGENTCACHE_CANONICAL_AGENT_ID_HPP
#define _AGENTCACHE_CANONICAL_AGENT_ID_HPP

#include <charconv>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace agentcache
{
/**
 * @brief Whether an id uses the JWT agent profile's canonical uint32 spelling.
 *
 * ASCII digits only, zero-padded to three characters and otherwise without leading zeroes.
 * "000" is valid. The engine does not link the JWT utility; tests pin the same boundary vectors.
 */
inline bool isCanonicalAgentId(std::string_view id) noexcept
{
    if (id.size() < 3 || id.size() > 10 || (id.size() > 3 && id.front() == '0'))
    {
        return false;
    }
    for (const char c : id)
    {
        if (c < '0' || c > '9')
        {
            return false;
        }
    }
    std::uint32_t value = 0;
    const auto [end, error] = std::from_chars(id.data(), id.data() + id.size(), value);
    return error == std::errc {} && end == id.data() + id.size();
}
} // namespace agentcache

#endif // _AGENTCACHE_CANONICAL_AGENT_ID_HPP
