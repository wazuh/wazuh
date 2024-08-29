#ifndef _GEO_LOCATOR_HPP
#define _GEO_LOCATOR_HPP

#include <geo/ilocator.hpp>

#include <maxminddb.h>

namespace geo
{

class DbEntry; ///< Forward declaration

class Locator final : public ILocator
{
private:
    std::weak_ptr<DbEntry> m_weakDbEntry; ///< The weak pointer to the database entry.

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
     * @brief Looks up the given IP address in the database if it is not already cached.
     *
     * @param ip The IP address to look up.
     * @param dbEntry The database entry to use for the lookup.
     * @return A base::OptError object containing an error message if the lookup failed.
     */
    base::OptError lookup(const std::string& ip, const std::shared_ptr<DbEntry>& dbEntry);

public:
    virtual ~Locator() = default;

    Locator() = delete;

    /**
     * @brief Construct a new Locator object
     *
     * @param dbEntry The database entry to use for the locator.
     */
    Locator(const std::shared_ptr<DbEntry>& dbEntry)
        : m_weakDbEntry(dbEntry)
    {
        if (m_weakDbEntry.expired())
        {
            throw std::runtime_error("Cannot build a maxmind locator with an expired db entry");
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
