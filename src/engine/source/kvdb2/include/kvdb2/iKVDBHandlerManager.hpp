#ifndef _IKVDBHANDLERMANAGER_H
#define _IKVDBHANDLERMANAGER_H

#include <kvdb2/iKVDBHandler.hpp>
#include <memory>
#include <string>

namespace kvdbManager
{

class IKVDBHandlerManager
{
public:
    virtual KVDBHandler getKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;
    virtual void removeKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;
    virtual bool skipAutoRemoveEnabled() = 0;
};

} // namespace kvdbManager

#endif // _IKVDBHANDLERMANAGER_H
