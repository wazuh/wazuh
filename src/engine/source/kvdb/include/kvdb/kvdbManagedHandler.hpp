#ifndef _KVDB_MANAGED_HANDLER_H
#define _KVDB_MANAGED_HANDLER_H

#include <kvdb/iKVDBHandlerManager.hpp>

namespace kvdbManager
{

/**
 * @brief Subset class that encapsulates functions auto removal of handlers.
 *
 */
class KVDBManagedHandler
{
public:
    KVDBManagedHandler(IKVDBHandlerManager* manager, const std::string& dbName, const std::string& scopeName)
        : m_handlerManager(manager)
        , m_dbName(dbName)
        , m_scopeName(scopeName)
    {
        // TODO: Add simple validation. Nullptrs, lengths, etc.
    }

    virtual ~KVDBManagedHandler()
    {
        // TODO: Add simple validation. Nullptrs, lengths, etc.
        if (m_handlerManager && !m_handlerManager->managerShuttingDown())
        {
            m_handlerManager->removeKVDBHandler(m_dbName, m_scopeName);
        }
    }

protected:
    /**
     * @brief Pointer to the Manager that deals with handlers.
     *
     */
    IKVDBHandlerManager* m_handlerManager {nullptr};

    /**
     * @brief Name of the Scope.
     *
     */
    std::string m_scopeName;

    /**
     * @brief Name of the DB.
     *
     */
    std::string m_dbName;
};

} // namespace kvdbManager

#endif // _KVDB_MANAGED_HANDLER_H
