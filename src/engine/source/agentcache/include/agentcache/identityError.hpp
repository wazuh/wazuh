// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _AGENTCACHE_IDENTITY_ERROR_HPP
#define _AGENTCACHE_IDENTITY_ERROR_HPP

#include <stdexcept>

namespace agentcache
{
/// An identity-contract rejection, distinct from malformed JSON or event framing errors.
class IdentityError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};
} // namespace agentcache

#endif // _AGENTCACHE_IDENTITY_ERROR_HPP
