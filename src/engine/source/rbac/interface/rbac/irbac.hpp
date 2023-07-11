#ifndef _RBAC_IAUTHENTICATOR_HPP
#define _RBAC_IAUTHENTICATOR_HPP

#include <functional>
#include <string>

namespace rbac
{

enum class Operation
{
    READ,
    WRITE,
    UNKNOWN
};

auto constexpr opToStr(Operation op)
{
    switch (op)
    {
        case Operation::READ: return "READ";
        case Operation::WRITE: return "WRITE";
        default: return "UNKNOWN";
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
    SYSTEM_ASSET,
    ASSET,
    UNKNOWN
};

auto constexpr resToStr(Resource res)
{
    switch (res)
    {
        case Resource::SYSTEM_ASSET: return "SYSTEM_ASSET";
        case Resource::ASSET: return "ASSET";
        default: return "UNKNOWN";
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
    using AuthFn = std::function<bool(const std::string&)>;

    virtual ~IRBAC() = default;

    virtual AuthFn getAuthFn(Resource res, Operation op) const = 0;
};
} // namespace rbac

#endif // _RBAC_IAUTHENTICATOR_HPP
