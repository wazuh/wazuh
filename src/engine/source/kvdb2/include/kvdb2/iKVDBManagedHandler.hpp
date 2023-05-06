#ifndef _IKVDBMANAGEDHANDLER_H
#define _IKVDBMANAGEDHANDLER_H

#include <kvdb2/iKVDBHandlerManager.hpp>

namespace kvdbManager
{

class IKVDBManagedHandler
{
public:
    IKVDBManagedHandler(IKVDBHandlerManager* manager, const std::string& scopeName) : m_manager(manager), m_scopeName(scopeName) {}
protected:
    IKVDBHandlerManager* m_manager { nullptr };
    std::string m_scopeName;
};

} // namespace kvdbManager

#endif // _IKVDBMANAGEDHANDLER_H
