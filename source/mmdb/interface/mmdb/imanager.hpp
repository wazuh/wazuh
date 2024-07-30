#ifndef _MMDB_IMANAGER_HPP
#define _MMDB_IMANAGER_HPP
#include <memory>
#include <string>

#include <base/error.hpp>

#include <mmdb/ihandler.hpp>

namespace mmdb
{
/**
 * @brief A manager for MMDB handlers, which are used to look up IP addresses in MMDB databases.
 * The manager is responsible for creating and managing the handlers.
 *
 * mmdb is the module that provides the interface to the MaxMind DB file format, offered by MaxMind Inc.
 * https://www.maxmind.com
 * This module also uses the MaxMind DB C library, which is a C library for reading MaxMind DB files.
 * https://maxmind.github.io/libmaxminddb/
 * @see IHandler
 * @note thread-safe if is compiled with free and malloc thread-safe
 */
class IManager
{

public:
    virtual ~IManager() = default;

    /**
     * @brief Add a new handler to the manager.
     * @param name The name of the handler.
     * @param mmdbPath The path to the MMDB database.
     * @throw if the handler already exists or cannot be created.
     */
    virtual void addHandler(const std::string& name, const std::string& mmdbPath) = 0;

    /**
     * @brief Remove a handler from the manager if it exists.
     * @param name The name of the handler to remove.
     */
    virtual void removeHandler(const std::string& name) = 0;

    /**
     * @brief Get a handler from the manager.
     * @param name The name of the handler to get.
     * @return The handler if it exists or an error if it does not.
     */
    virtual base::RespOrError<std::shared_ptr<IHandler>> getHandler(const std::string& name) const = 0;
};
} // namespace mmdb

#endif // _MMDB_IMANAGER_HPP
