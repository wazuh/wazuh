#ifndef _GEO_LOCATOR_HPP
#define _GEO_LOCATOR_HPP

#include <geo/ilocator.hpp>

#include <maxminddb.h>

namespace geo
{

class DbHandle; ///< Forward declaration
class DbInstance; ///< Forward declaration

class Locator final : public ILocator
{
private:
    std::weak_ptr<DbHandle> m_handle;
    std::shared_ptr<const DbInstance> m_cachedDb; // To invalidate cache if the database changes
    std::string m_cachedIp;              ///< The cached IP address.
    MMDB_lookup_result_s m_cachedResult; ///< The cached lookup result.

    /**
     * @brief Retrieves the entry data for a given dot path.
     *
     * @param path The dot path to retrieve the entry data for.
     * @return A base::RespOrError object containing the entry data or an error message.
     */
    base::RespOrError<MMDB_entry_data_s> getEData(const DotPath& path);

    /**
     * @brief Validates the database handle and returns the current database instance.
     *        Also invalidates the cache if the database instance has changed.
     *
     * @return A base::RespOrError object containing the database instance or an error message.
     */
    base::RespOrError<std::shared_ptr<const DbInstance>> validateAndGetDb();

    /**
     * @brief Looks up the given IP address in the database if it is not already cached.
     *
     * @param ip The IP address to look up.
     * @param db The database instance to use for the lookup.
     * @return A base::OptError object containing an error message if the lookup failed.
     */
    base::OptError lookup(const std::string& ip, const std::shared_ptr<const DbInstance>& db);

public:
    virtual ~Locator() = default;

    Locator() = delete;

    /**
     * @brief Construct a new Locator object
     *
     * @param handle The database handle to use for the locator.
     */
    Locator(const std::shared_ptr<DbHandle>& handle)
    : m_handle(handle)
    {
        if (!handle)
        {
            throw std::runtime_error("Cannot build locator with null db handle");
        }
    }

    /**
     * @copydoc ILocator::getString
     */
    base::RespOrError<std::string> getString(const std::string& ip, const DotPath& path) override;

    /**
     * @copydoc ILocator::getUint32
     */
    base::RespOrError<uint32_t> getUint32(const std::string& ip, const DotPath& path) override;

    /**
     * @copydoc ILocator::getDouble
     */
    base::RespOrError<double> getDouble(const std::string& ip, const DotPath& path) override;

    /**
     * @copydoc ILocator::getAsJson
     */
    base::RespOrError<json::Json> getAsJson(const std::string& ip, const DotPath& path) override;

    /**
     * @copydoc ILocator::getAll
     */
    base::RespOrError<json::Json> getAll(const std::string& ip) override;

    /**
     * @brief Retrieves the cached IP address.
     *
     * @return The cached IP address.
     */
    inline const std::string& getCachedIp() const { return m_cachedIp; }

    /**
     * @brief Retrieves the cached lookup result.
     *
     * @return The cached lookup result.
     */
    inline const MMDB_lookup_result_s& getCachedResult() const { return m_cachedResult; }
};

} // namespace geo
#endif // _GEO_LOCATOR_HPP
