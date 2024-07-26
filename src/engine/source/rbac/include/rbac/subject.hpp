#ifndef _RBAC_SUBJECT_HPP
#define _RBAC_SUBJECT_HPP

#include <string>
#include <unordered_set>

#include <rbac/role.hpp>

namespace rbac
{
class Subject
{
private:
    std::string m_name;
    std::unordered_set<Role> m_roles;

public:
    Subject(std::unordered_set<Role> roles)
        : m_roles(roles)
    {
    }

    const std::string& getName() const { return m_name; }

    const std::unordered_set<Role>& getRoles() const { return m_roles; }

    bool hasRole(const Role& role) const { return m_roles.find(role) != m_roles.end(); }

    friend inline bool operator==(const Subject& lhs, const Subject& rhs)
    {
        return lhs.m_name == rhs.m_name && lhs.m_roles == rhs.m_roles;
    }

    friend inline bool operator!=(const Subject& lhs, const Subject& rhs) { return !(lhs == rhs); }
};
} // namespace rbac

// Make Subject hashable
template<>
struct std::hash<rbac::Subject>
{
    std::size_t operator()(const rbac::Subject& subject) const noexcept
    {
        return std::hash<std::string> {}(subject.getName());
    }
};

#endif // _RBAC_SUBJECT_HPP
