#ifndef _RBAC_IAUTHENTICATOR_HPP
#define _RBAC_IAUTHENTICATOR_HPP

#include <functional>
#include <string>

namespace rbac
{

enum class Operation
{
    UNKNOWN,
    READ,
    WRITE
};

auto constexpr opToStr(Operation op)
{
    switch (op)
    {
        case Operation::READ: return "read";
        case Operation::WRITE: return "write";
        default: return "unknown";
    }
}

auto constexpr strToOp(std::string_view str)
{
    if (str == opToStr(Operation::READ))
    {
        return Operation::READ;
    }
    else if (str == opToStr(Operation::WRITE))
    {
        return Operation::WRITE;
    }

    return Operation::UNKNOWN;
}

enum class Resource
{
    UNKNOWN,
    SYSTEM_ASSET,
    ASSET
};

auto constexpr resToStr(Resource res)
{
    switch (res)
    {
        case Resource::SYSTEM_ASSET: return "system_asset";
        case Resource::ASSET: return "asset";
        default: return "unknown";
    }
}

auto constexpr strToRes(std::string_view str)
{
    if (str == resToStr(Resource::SYSTEM_ASSET))
    {
        return Resource::SYSTEM_ASSET;
    }
    else if (str == resToStr(Resource::ASSET))
    {
        return Resource::ASSET;
    }

    return Resource::UNKNOWN;
}

class IRBAC
{
public:
    /**
     * @brief Function to autorize a role to perform an operation on a resource.
     *
     * @param role Role to authorize
     * @return true If the role is authorized to perform the operation on the resource
     * @return false If the role is not authorized to perform the operation on the resource
     */
    using AuthFn = std::function<bool(const std::string&)>;

    virtual ~IRBAC() = default;

    virtual AuthFn getAuthFn(Resource res, Operation op) const = 0;
};
} // namespace rbac

#endif // _RBAC_IAUTHENTICATOR_HPP
