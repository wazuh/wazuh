#ifndef _MMDB_IRESULT_HPP
#define _MMDB_IRESULT_HPP

#include <base/dotPath.hpp>
#include <base/error.hpp>
#include <base/json.hpp>

namespace mmdb
{

class IResult
{
public:
    virtual ~IResult() = default;

    /**
     * @brief Returns true if the result has data.
     * @return true if the result has data, false otherwise.
     */
    virtual bool hasData() const = 0;

    /**
     * @brief Get the string data at the given path.
     *
     * @param path The path to the data.
     * @return Either the data as a string or an error if the data could not be retrieved.
     * @throws std::runtime_error if the path is invalid or the data is not a string.
     */
    virtual base::RespOrError<std::string> getString(const DotPath& path) const = 0;

    /**
     * @brief Get the Uint32 data at the given path.
     *
     * @param path The path to the data.
     * @return base::RespOrError<uint32_t> Either the data as a uint32_t or an error if the data could not be retrieved.
     */
    virtual base::RespOrError<uint32_t> getUint32(const DotPath& path) const = 0;

    /**
     * @brief Get the Double data at the given path.
     *
     * @param path The path to the data.
     * @return base::RespOrError<double>  Either the data as a double or an error if the data could not be retrieved.
     */
    virtual base::RespOrError<double> getDouble(const DotPath& path) const = 0;

    /**
     * @brief Get the data at the given path as a json object.
     *
     * @param path The path to the data.
     * @return base::RespOrError<json::Json>  Either the data as a json object or an error if the data could not be
     * retrieved.
     * @note this method not supported array or object type.
     */
    virtual base::RespOrError<json::Json> getAsJson(const DotPath& path) const = 0;

    /**
     * @brief MaxMind result dump, like stored in the database.
     *
     * @return json::Json mmdb result dump, empty if no data.
     * @throws std::runtime_error if the result could not be dumped.
     */
    virtual json::Json mmDump() const = 0;
};
} // namespace mmdb

#endif // MMDB_INTERFACE_IRESULT_HPP
