#include <base/logging.hpp>

#include "handler.hpp"

namespace mmdb
{

base::OptError Handler::open()
{
    if (isOpen)
    {
        return base::Error {"MMDB database is already open"};
    }

    int status = MMDB_open(dbPath.c_str(), MMDB_MODE_MMAP, mmdb.get());
    if (MMDB_SUCCESS != status)
    {
        return base::Error {fmt::format("Error opening database: {}", MMDB_strerror(status))};
    }

    isOpen = true;
    return std::nullopt;
}

void Handler::close()
{
    if (isOpen)
    {
        LOG_DEBUG("Closing {} database", dbPath);
        MMDB_close(mmdb.get());
        isOpen = false;
    }
}

std::shared_ptr<IResult> Handler::lookup(const std::string& ipStr) const
{
    if (!isOpen)
    {
        throw std::runtime_error("MMDB database is not open");
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(mmdb.get(), ipStr.c_str(), &gai_error, &mmdb_error);

    if (0 != gai_error) // translation error
    {
        std::string msg {"Error translating IP address "};
        msg += ipStr;
        msg += ": ";
        msg += gai_strerror(gai_error);
        throw std::runtime_error(msg);
    }

    if (MMDB_SUCCESS != mmdb_error) // libmaxminddb error, should not happen
    {
        std::string msg {"Error from libmaxminddb: "};
        msg += MMDB_strerror(mmdb_error);
        throw std::runtime_error(msg);
    }

    return std::make_shared<Result>(result);
}

} // namespace mmdb
