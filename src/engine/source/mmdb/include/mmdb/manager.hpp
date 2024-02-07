#ifndef _MMDB_MANAGER_HPP
#define _MMDB_MANAGER_HPP

#include <map>

#include <mmdb/imanager.hpp>

namespace mmdb
{
/**
 * @copydoc IManager
 */
class Manager : public IManager
{

private:
    std::map<std::string, std::shared_ptr<IHandler>> m_handlers; ///< The handlers managed by the manager.

public:
    Manager() = default;
    ~Manager() = default;

    /**
     * @copydoc IManager::addHandler
     */
    void addHandler(const std::string& name, const std::string& mmdbPath) override;

    /**
     * @copydoc IManager::removeHandler
     */
    void removeHandler(const std::string& name) override;

    /**
     * @copydoc IManager::getHandler
     */
    base::RespOrError<std::shared_ptr<IHandler>> getHandler(const std::string& name) const override;
};
} // namespace mmdb

#endif // _MMDB_MANAGER_HPP
