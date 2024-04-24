#ifndef _GEO_IMANAGER_HPP
#define _GEO_IMANAGER_HPP

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include <base/error.hpp>

#include <geo/ilocator.hpp>

namespace geo
{

/**
 * @brief The type of the database.
 *
 */
enum class Type
{
    CITY,
    ASN
};

/**
 * @brief Get the string representation of the given type.
 *
 * @param type
 * @return constexpr auto
 */
static constexpr auto typeName(Type type)
{
    switch (type)
    {
        case Type::CITY: return "city";
        case Type::ASN: return "asn";
        default: throw std::logic_error("Not handled geo::Type in typeName");
    }
}

/**
 * @brief Get the type from the given name.
 *
 * @param name
 * @return constexpr Type
 */
static constexpr Type typeFromName(std::string_view name)
{
    if (name == typeName(Type::CITY))
    {
        return Type::CITY;
    }

    if (name == typeName(Type::ASN))
    {
        return Type::ASN;
    }

    throw std::logic_error(fmt::format("Invalid geo::Type name string '{}'", name));
}

/**
 * @brief Information about a database.
 *
 */
struct DbInfo
{
    std::string name;
    std::string path;
    Type type;
};

/**
 * @brief Get the valid type names.
 *
 * @return constexpr auto
 */
inline auto validTypeNames()
{
    return fmt::format("{}, {}", typeName(Type::CITY), typeName(Type::ASN));
}

/**
 * @brief Manages geo databases and allows getting locators for querying the databases.
 *
 */
class IManager
{
public:
    virtual ~IManager() = default;

    /**
     * @brief Adds a database to the manager, it must be a valid MMDB database and already present in the filesystem.
     *
     * @param path The path to the MMDB database.
     * @param type The type of the database.
     * @return base::OptError An error if the database could not be added.
     */
    virtual base::OptError addDb(const std::string& path, Type type) = 0;

    /**
     * @brief Removes a database from the manager. The database will persist in the filesystem.
     *
     * @param path The path to the MMDB database.
     * @return base::OptError An error if the database could not be removed.
     */
    virtual base::OptError removeDb(const std::string& path) = 0;

    /**
     * @brief Get a list of databases.
     *
     * @return std::vector<DbInfo>
     */
    virtual std::vector<DbInfo> listDbs() const = 0;

    /**
     * @brief Remote upsert a database from a given URL. The database will be downloaded and stored in the
     * filesystem.
     *
     * @param path Path to store the database.
     * @param type Type of the database.
     * @param dbUrl URL to download the database.
     * @param hashUrl URL to download the hash of the database.
     * @return base::OptError An error if the database could not be downloaded or stored.
     */
    virtual base::OptError
    remoteUpsertDb(const std::string& path, Type type, const std::string& dbUrl, const std::string& hashUrl) = 0;

    /**
     * @brief Get a locator for querying the given type of database.
     *
     * @param type The type of the database.
     * @return base::RespOrError<std::shared_ptr<ILocator>> A locator for querying the database or an error if the
     * locator could not be retrieved.
     */
    virtual base::RespOrError<std::shared_ptr<ILocator>> getLocator(Type type) const = 0;
};

} // namespace geo
#endif // _GEO_IMANAGER_HPP
