#ifndef _KVDBHANDLERCOLLECTION_H
#define _KVDBHANDLERCOLLECTION_H

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <kvdb2/kvdbSpace.hpp>

namespace kvdbManager
{

class KVDBScope;
class IKVDBHandlerManager;

class KVDBHandlerCollection
{
private:
    class KVDBHandlerInstance
    {
    public:
        explicit KVDBHandlerInstance(const std::shared_ptr<KVDBSpace>& spHandler) : m_spHandler(std::move(spHandler)) {}
        std::shared_ptr<KVDBSpace> getHandler() const { return m_spHandler; }
        void addScope(const std::string& scopeName) { m_setScopes.insert(scopeName); }
        void removeScope(const std::string& scopeName) { m_setScopes.erase(scopeName); }
        bool emptyScopes() const { return m_setScopes.empty(); }
    private:
        std::shared_ptr<KVDBSpace> m_spHandler;
        std::multiset<std::string> m_setScopes;
    };

public:
    KVDBHandlerCollection(IKVDBHandlerManager* handleManager) : m_handleManager(handleManager) {}
    std::shared_ptr<IKVDBHandler> getKVDBHandler(const std::string& dbName, const std::string& scopeName);
    void removeKVDBHandler(const std::string& dbName, const std::string& scopeName);

private:
    std::map<std::string, std::shared_ptr<KVDBHandlerInstance>> m_mapInstances;
    IKVDBHandlerManager* m_handleManager { nullptr };
    std::mutex m_mutex;

};

} // namespace kvdbManager

#endif // _KVDBHANDLERCOLLECTION_H
