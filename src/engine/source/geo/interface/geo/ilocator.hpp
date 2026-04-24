#ifndef GEO_ILOCATOR_HPP
#define GEO_ILOCATOR_HPP

#include <string>

#include <base/dotPath.hpp>
#include <base/json.hpp>
#include <geo/errorCodes.hpp>

namespace geo
{
/**
 * @brief Interface for querying data from a geo database.
 *
 */
class ILocator
{
public:
    virtual ~ILocator() = default;

    /**
     * @brief Get the string data at the given path.
     *
     * @param ip Target ip to query
     * @param path The path to the data.
     * @return Either the data as a string or an error code if the data could not be retrieved.
     * @throws std::runtime_error if the path is invalid or the data is not a string.
     */
    virtual Result<std::string> getString(const std::string& ip, const DotPath& path) = 0;

    /**
     * @brief Get the Uint32 data at the given path.
     *
     * @param ip Target ip to query
     * @param path The path to the data.
     * @return Result<uint32_t> Either the data as a uint32_t or an error if the data could not be retrieved.
     */
    virtual Result<uint32_t> getUint32(const std::string& ip, const DotPath& path) = 0;

    /**
     * @brief Get the Double data at the given path.
     *
     * @param ip Target ip to query
     * @param path The path to the data.
     * @return Result<double>  Either the data as a double or an error if the data could not be retrieved.
     */
    virtual Result<double> getDouble(const std::string& ip, const DotPath& path) = 0;

    /**
     * @brief Get the data at the given path as a json object.
     *
     * @param ip Target ip to query
     * @param path The path to the data.
     * @return Result<json::Json>  Either the data as a json object or an error if the data could not be
     * retrieved.
     * @note this method not supported array or object type.
     */
    virtual Result<json::Json> getAsJson(const std::string& ip, const DotPath& path) = 0;

    /**
     * @brief Get all data for the given IP as a complete JSON object.
     *
     * @param ip Target ip to query
     * @return Result<json::Json> Either the complete data as a json object or an error if the data could
     * not be retrieved.
     */
    virtual Result<json::Json> getAll(const std::string& ip) = 0;
};

} // namespace geo

#endif // GEO_ILOCATOR_HPP
