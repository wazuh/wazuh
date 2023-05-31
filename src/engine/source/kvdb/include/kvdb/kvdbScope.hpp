#ifndef _KVDBSCOPE_H
#define _KVDBSCOPE_H

#include <kvdb/iKVDBScope.hpp>

namespace kvdbManager
{
class IKVDBHandlerManager;

class KVDBScope : public IKVDBScope
{
public:
    KVDBScope(IKVDBHandlerManager* handlerManager, const std::string& name)
        : m_handlerManager(handlerManager)
        , m_name(name)
    {
    }
    virtual std::variant<std::unique_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName) override;

private:
    IKVDBHandlerManager* m_handlerManager {nullptr};
    std::string m_name;
};

} // namespace kvdbManager

#endif // _KVDBSCOPE_H
