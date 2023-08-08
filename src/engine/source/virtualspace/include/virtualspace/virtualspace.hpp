#ifndef _VIRTUALSPACE_HPP
#define _VIRTUALSPACE_HPP

#include <virtualspace/ivirtualspace.hpp>

#include <string>
#include <tuple>
#include <vector>
#include <unordered_set>

/**
 * @brief
 *
 */
namespace virtualspace
{
/**
 * @brief A header-only implementation of the IVirtualSpace and IVirtualSpaceAuth interfaces.
 *
 */
class VirtualSpace
    : public IVirtualSpaceManager
    , public IVirtualSpaceAuth
{
private:
    std::unordered_set<VSName> namespaces_;
    std::unordered_map<VSName, std::unordered_set<Resource>> resources_;
    std::unordered_set<Role> roles_;
    std::unordered_map<Role, std::unordered_map<VSName, std::unordered_set<Operation>>> rolePermissions_;

public:
    bool addNamespace(const VSName& name) override { return namespaces_.insert(name).second; }

    bool removeNamespace(const VSName& name) override { return namespaces_.erase(name) > 0; }

    std::unordered_set<VSName> getNamespaces() const override { return namespaces_; }

    bool addResourceToNamespace(const VSName& vsName, const Resource& res) override
    {
        auto it = resources_.find(vsName);
        if (it == resources_.end())
        {
            return false;
        }
        return it->second.insert(res).second;
    }

    void removeResourceFromNamespace(const VSName& vsName, const Resource& res) override
    {
        auto it = resources_.find(vsName);
        if (it != resources_.end())
        {
            it->second.erase(res);
        }
    }

    std::unordered_set<Resource> getResourcesInNamespace(const VSName& vsName) const override
    {
        auto it = resources_.find(vsName);
        if (it == resources_.end())
        {
            return {};
        }
        return it->second;
    }

    bool addRole(const Role& name) override { return roles_.insert(name).second; }

    bool removeRole(const Role& name) override { return roles_.erase(name) > 0; }

    std::unordered_set<Role> getRoles() const override { return roles_; }

    bool setRolePermissions(const Role& name, const VSName& vsName, const std::vector<Operation>& ops) override
    {
        auto& perms = rolePermissions_[name][vsName];
        for (auto op : ops)
        {
            perms.insert(op);
        }
        return true;
    }

    bool removeRolePermissions(const Role& name, const VSName& vsName, const std::vector<Operation>& ops) override
    {
        auto it = rolePermissions_.find(name);
        if (it == rolePermissions_.end())
        {
            return false;
        }
        auto& perms = it->second[vsName];
        for (auto op : ops)
        {
            perms.erase(op);
        }
        return true;
    }

    std::unordered_set<Operation> getRolePermissions(const Role& name, const VSName& vsName) const override
    {
        auto it = rolePermissions_.find(name);
        if (it == rolePermissions_.end())
        {
            return {};
        }
        auto it2 = it->second.find(vsName);
        if (it2 == it->second.end())
        {
            return {};
        }
        return it2->second;
    }

    Result check(const Role& role, Operation op, const VSName& vsName) const override
    {
        auto it = rolePermissions_.find(role);
        if (it == rolePermissions_.end())
        {
            return Result::NOT_FOUND;
        }
        auto it2 = it->second.find(vsName);
        if (it2 == it->second.end())
        {
            return Result::NOT_FOUND;
        }
        auto& perms = it2->second;
        if (perms.find(op) != perms.end())
        {
            return Result::ALLOWED;
        }
        return Result::DENIED;
    }

    Result check(const Role& role, Operation op, const Resource& res) const override
    {
        for (const auto& [vsName, resources] : resources_)
        {
            if (resources.find(res) != resources.end())
            {
                return check(role, op, vsName);
            }
        }
        return Result::NOT_FOUND;
    }
};
} // namespace virtualspace

#endif // _VIRTUALSPACE_HPP
