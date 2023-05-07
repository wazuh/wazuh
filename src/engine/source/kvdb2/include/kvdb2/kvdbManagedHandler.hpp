#ifndef _KVDBMANAGEDHANDLER_H
#define _KVDBMANAGEDHANDLER_H

#include <kvdb2/iKVDBHandlerManager.hpp>

namespace kvdbManager
{

class KVDBManagedHandler
{
public:
    KVDBManagedHandler(IKVDBHandlerManager* manager, const std::string& scopeName) : m_handlerManager(manager), m_scopeName(scopeName) {}
protected:
    IKVDBHandlerManager* m_handlerManager { nullptr };
    std::string m_scopeName;
};

} // namespace kvdbManager

#endif // _KVDBMANAGEDHANDLER_H
