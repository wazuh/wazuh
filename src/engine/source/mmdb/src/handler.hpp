#ifndef _MMDB_MMDBHANDLER_HPP
#define _MMDB_MMDBHANDLER_HPP

#include <memory>
#include <string>

#include <maxminddb.h>

#include <error.hpp>
#include <logging/logging.hpp>

#include <mmdb/ihandler.hpp>

#include "result.hpp"

namespace mmdb
{
class MMDBHandler : public IHandler
{
private:
    bool isOpen;
    std::string dbPath;
    std::unique_ptr<MMDB_s> mmdb;

public:
    /**
     * @brief Create a new MMDBHandler.
     * @param dbPath The path to the MMDB database.
     */
    MMDBHandler(const std::string& dbPath)
        : isOpen(false)
        , dbPath(dbPath)
        , mmdb(std::make_unique<MMDB_s>())
    {
    }

    ~MMDBHandler() { close(); }

    /**
     * @brief Open the MMDB database.
     * @return An error if the database could not be opened.
     */
    base::OptError open();

    /**
     * @brief Close the MMDB database if it is open.
     */
    void close();

    /**
     * @copydoc IHandler::isAvailable
     */
    bool isAvailable() const override { return isOpen; }

    /**
     * @copydoc IHandler::lookup
     */
    std::shared_ptr<IResult> lookup(const std::string& ip) const override;
};
} // namespace mmdb

#endif // _MMDB_MMDBHANDLER_HPP
