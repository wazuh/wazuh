#ifndef _KVDBMANAGEDHANDLER_H
#define _KVDBMANAGEDHANDLER_H

#include <kvdb2/iKVDBHandlerManager.hpp>

namespace kvdbManager
{

class KVDBManagedHandler
{
public:
    KVDBManagedHandler(IKVDBHandlerManager* manager, const std::string& dbName, const std::string& scopeName):
        m_handlerManager(manager),
        m_dbName(dbName),
        m_scopeName(scopeName)
    {
        //TODO: Add simple validation. Nullptrs, lengths, etc.
    }

    virtual ~KVDBManagedHandler()
    {
        if (m_handlerManager)
        {
            if (!m_handlerManager->skipAutoRemoveEnabled())
            {
                m_handlerManager->removeKVDBHandler(m_dbName, m_scopeName);
            }
        }
    }

protected:
    IKVDBHandlerManager* m_handlerManager { nullptr };
    std::string m_scopeName;
    std::string m_dbName;
};

} // namespace kvdbManager

#endif // _KVDBMANAGEDHANDLER_H
