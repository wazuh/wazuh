#ifndef _MMDB_RESULT_HPP // Use _MMDB and not MMDB to avoid conflict with MaxMindDB
#define _MMDB_RESULT_HPP

#include <memory>
#include <utility>

#include <maxminddb.h>

#include <mmdb/iresult.hpp>

namespace mmdb
{

class Result : public IResult
{
private:
    MMDB_lookup_result_s m_result; ///< The MMDB lookup result.

    /**
     * @brief Retrieves the entry data for a given dot path.
     * @param path The dot path to retrieve the entry data for.
     * @return A base::RespOrError object containing the entry data or an error message.
     */
    base::RespOrError<MMDB_entry_data_s> getEData(const DotPath& path) const;

public:
    Result(MMDB_lookup_result_s result)
        : m_result(result)
    {
    }

    ~Result() = default;

    /**
     * @copydoc IResult::hasData()
     */
    bool hasData() const override { return m_result.found_entry; }

    /**
     * @copydoc IResult::getString()
     */
    base::RespOrError<std::string> getString(const DotPath& path) const override;

    /**
     * @copydoc IResult::getUint32()
     */
    base::RespOrError<uint32_t> getUint32(const DotPath& path) const override;

    /**
     * @copydoc IResult::getDouble()
     */
    base::RespOrError<double> getDouble(const DotPath& path) const override;

    /**
     * @copydoc IResult::getAsJson()
     */
    base::RespOrError<json::Json> getAsJson(const DotPath& path) const override;

    /**
     * @copydoc IResult::mmDump()
     */
    json::Json mmDump() const override;
};

} // namespace mmdb

#endif // _MMDB_RESULT_HPP
