#ifndef _KVDBSCOPE_H
#define _KVDBSCOPE_H

#include <memory>

#include <kvdb2/iKVDBHandlerManager.hpp>
#include <kvdb2/iKVDBScope.hpp>

namespace kvdbManager
{

class KVDBScope : public IKVDBScope
{
public:
    KVDBScope(IKVDBHandlerManager* handlerManager, const std::string& name);
    ~KVDBScope();

    bool initialize();

    std::string getName() const override { return m_name; }
    void setName(const std::string& name) override { m_name = name; }

    std::shared_ptr<IKVDBHandler> getKVDBHandler(const std::string& dbName) override;

private:
    bool m_initialized { false };
    IKVDBHandlerManager* m_handlerManager { nullptr };
    std::string m_name;
};

} // namespace kvdbManager

#endif // _KVDBSCOPE_H
