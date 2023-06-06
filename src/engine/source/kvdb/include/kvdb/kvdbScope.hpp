#ifndef _KVDB_SCOPE_H
#define _KVDB_SCOPE_H

#include <kvdb/iKVDBScope.hpp>

namespace kvdbManager
{
class IKVDBHandlerManager;

/**
 * @brief KVDBScope class.
 * This is basically an identifier for any entity using the DB.
 * Also provides syntax sugar to access the Manager, pairing the requests with the Scope Name.
 */
class KVDBScope : public IKVDBScope
{
public:
    /**
     * @brief Construct a new KVDBScope object
     *
     * @param handlerManager Pointer to the Manager that deals with handlers.
     * @param name Name of the Scope.
     */
    KVDBScope(IKVDBHandlerManager* handlerManager, const std::string& name)
        : m_handlerManager(handlerManager)
        , m_name(name)
    {
    }

    /**
     * @copydoc IKVDBScope::getKVDBHandler
     *
     */
    virtual std::variant<std::shared_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName) override;

private:
    /**
     * @brief Pointer to the internal manager that deals with handlers.
     *
     */
    IKVDBHandlerManager* m_handlerManager {nullptr};

    /**
     * @brief Name of the Scope.
     *
     */
    std::string m_name;
};

} // namespace kvdbManager

#endif // _KVDB_SCOPE_H
