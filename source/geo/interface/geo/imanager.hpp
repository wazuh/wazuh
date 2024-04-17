#ifndef _GEO_IMANAGER_HPP
#define _GEO_IMANAGER_HPP

#include <memory>
#include <stdexcept>

#include <base/error.hpp>
#include <string>

#include <geo/ilocator.hpp>

namespace geo
{

enum class Type
{
    CITY,
    ASN
};

static constexpr auto typeName(Type type)
{
    switch (type)
    {
        case Type::CITY: return "city";
        case Type::ASN: return "asn";
        default: throw std::logic_error("Not handled geo::Type in typeName");
    }
}

class IManager
{
public:
    virtual ~IManager() = default;

    virtual base::RespOrError<std::shared_ptr<ILocator>> getLocator(Type type) const = 0;

    virtual base::OptError addDb(const std::string& path, Type type) = 0;
    virtual base::OptError removeDb(const std::string& path) = 0;
    virtual base::OptError
    remoteUpdateDb(const std::string& path, const std::string& dbUrl, const std::string& hashUrl) = 0;
};

} // namespace geo
#endif // _GEO_IMANAGER_HPP
