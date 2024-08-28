#ifndef _RBAC_PERMISSION_HPP
#define _RBAC_PERMISSION_HPP

#include <string>
#include <variant>

#include <base/json.hpp>
#include <rbac/irbac.hpp>

namespace rbac
{

namespace detail
{
auto constexpr OP_JPATH = "/operation";
auto constexpr RES_JPATH = "/resource";
} // namespace detail

class Permission
{
private:
    Resource m_resource;
    Operation m_operation;

public:
    Permission(Resource resource, Operation operation)
        : m_resource(resource)
        , m_operation(operation)
    {
    }

    friend inline bool operator<(const Permission& lhs, const Permission& rhs)
    {
        return lhs.m_resource < rhs.m_resource
               || (lhs.m_resource == rhs.m_resource && lhs.m_operation < rhs.m_operation);
    }

    const Resource& getResource() const { return m_resource; }

    const Operation& getOperation() const { return m_operation; }

    std::string getName() const { return std::string(resToStr(m_resource)) + "." + std::string(opToStr(m_operation)); }

    friend inline bool operator==(const Permission& lhs, const Permission& rhs)
    {
        return lhs.m_resource == rhs.m_resource && lhs.m_operation == rhs.m_operation;
    }

    friend inline bool operator!=(const Permission& lhs, const Permission& rhs) { return !(lhs == rhs); }

    json::Json toJson() const
    {
        json::Json json;
        json.setObject();
        json.setString(resToStr(m_resource), detail::RES_JPATH);
        json.setString(opToStr(m_operation), detail::OP_JPATH);
        return json;
    }

    static base::RespOrError<Permission> fromJson(const json::Json& json)
    {
        auto res = json.getString(detail::RES_JPATH);
        if (!res)
        {
            return base::Error {"Permission::fromJson: " + std::string(detail::RES_JPATH) + " not found"};
        }
        auto op = json.getString(detail::OP_JPATH);
        if (!op)
        {
            return base::Error {"Permission::fromJson: " + std::string(detail::OP_JPATH) + " not found"};
        }
        return Permission(strToRes(res.value()), strToOp(op.value()));
    }
};
} // namespace rbac

// Make Permission hashable
template<>
struct std::hash<rbac::Permission>
{
    std::size_t operator()(const rbac::Permission& permission) const noexcept
    {
        return std::hash<int> {}(static_cast<int>(permission.getResource()))
               ^ std::hash<int> {}(static_cast<int>(permission.getOperation()));
    }
};

#endif // _RBAC_PERMISSION_HPP
