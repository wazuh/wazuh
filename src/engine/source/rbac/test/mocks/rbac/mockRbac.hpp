#ifndef _RBAC_MOCK_RBAC_HPP
#define _RBAC_MOCK_RBAC_HPP

#include <gmock/gmock.h>

#include <rbac/irbac.hpp>

namespace rbac::mocks
{
class MockRBAC : public rbac::IRBAC
{
public:
    MOCK_METHOD(rbac::IRBAC::AuthFn, getAuthFn, (rbac::Resource, rbac::Operation), (const, override));
};
} // namespace rbac::mocks

#endif // _RBAC_MOCK_RBAC_HPP
