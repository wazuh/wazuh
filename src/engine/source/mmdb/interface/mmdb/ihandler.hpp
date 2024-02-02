#ifndef _MMBDB_IHANDLER_HPP
#define _MMBDB_IHANDLER_HPP

#include <string>
#include <memory>

#include <mmdb/iresult.hpp>

namespace mmdb {

class IHandler
{
    public:
        virtual ~IHandler() = default;

        /**
         * @brief Check if the handler is available.
         * @return True if the handler is available, false otherwise.
         */
        virtual bool isAvailable() const = 0;

        /**
         * @brief Search a IP address in the MMDB database.
         *
         * @param ip The IP address to search.
         * @return A Result object containing the result of the search.
         */
        virtual std::shared_ptr<IResult> lookup(const std::string& ip) const = 0;
};

}

#endif // _MMBDB_HANDLER_HPP
