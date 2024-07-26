#ifndef _RBAC_ROLE_HPP
#define _RBAC_ROLE_HPP

#include <string>
#include <set>
#include <variant>

#include <rbac/permission.hpp>

namespace rbac
{

class Role
{
private:
    std::string m_name;
    std::set<Permission> m_permissions;

public:
    Role() = default;

    Role(const std::string& name, const std::set<Permission>& permissions)
        : m_name(name)
        , m_permissions(permissions)
    {
    }

    Role(const std::string& name, std::set<Permission>&& permissions)
        : m_name(name)
        , m_permissions(std::move(permissions))
    {
    }

    const std::string& getName() const { return m_name; }

    const std::set<Permission>& getPermissions() const { return m_permissions; }

    friend inline bool operator==(const Role& lhs, const Role& rhs)
    {
        return lhs.m_name == rhs.m_name && lhs.m_permissions == rhs.m_permissions;
    }

    friend inline bool operator!=(const Role& lhs, const Role& rhs) { return !(lhs == rhs); }

    friend inline bool operator<(const Role& lhs, const Role& rhs) { return lhs.m_name < rhs.m_name; }

    json::Json toJson() const
    {
        auto path = json::Json::formatJsonPath(m_name);
        json::Json json;
        json.setArray(path);

        for (const auto& permission : m_permissions)
        {
            json.appendJson(permission.toJson(), path);
        }

        return json;
    }

    static std::variant<Role, base::Error> fromJson(const std::string& key, const json::Json& permissions)
    {
        std::set<Permission> perms;
        auto permsArray = permissions.getArray();
        if (!permsArray)
        {
            return base::Error {fmt::format("Expected permissions to be an array for role {}", key)};
        }

        for (const auto& jPerm : *permsArray)
        {
            auto perm = Permission::fromJson(jPerm);
            if (std::holds_alternative<base::Error>(perm))
            {
                return std::get<base::Error>(perm);
            }

            perms.emplace(std::get<Permission>(perm));
        }

        return Role(key, perms);
    }
};
} // namespace rbac

// Make Role hashable
template<>
struct std::hash<rbac::Role>
{
    std::size_t operator()(const rbac::Role& role) const noexcept { return std::hash<std::string> {}(role.getName()); }
};

#endif // _RBAC_ROLE_HPP
