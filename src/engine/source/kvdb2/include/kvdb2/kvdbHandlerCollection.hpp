#ifndef _KVDBHANDLERCOLLECTION_H
#define _KVDBHANDLERCOLLECTION_H

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>


#include <kvdb2/kvdbSpace.hpp>
#include <kvdb2/refCounter.hpp>

namespace kvdbManager
{

class KVDBScope;
class IKVDBHandlerManager;

class KVDBHandlerCollection
{
public:
    KVDBHandlerCollection(IKVDBHandlerManager* handleManager) : m_handleManager(handleManager) {}
    std::shared_ptr<IKVDBHandler> getKVDBHandler(rocksdb::DB* db, rocksdb::ColumnFamilyHandle* cfHandle, const std::string& dbName, const std::string& scopeName);
    void removeKVDBHandler(const std::string& dbName, const std::string& scopeName, bool &isRemoved);
    std::vector<std::string> getDBNames();
    std::map<std::string, int> getRefMap(const std::string& dbName);

private:
    class KVDBHandlerInstance
    {
    public:
        explicit KVDBHandlerInstance(const std::shared_ptr<KVDBSpace>& spHandler) : m_spHandler(spHandler) {}
        ~KVDBHandlerInstance();

        std::shared_ptr<KVDBSpace> getHandler() const { return m_spHandler; }
        void addScope(const std::string& scopeName) { m_scopeCounter.addRef(scopeName); }
        void removeScope(const std::string& scopeName) { m_scopeCounter.removeRef(scopeName); }
        bool emptyScopes() const { return m_scopeCounter.empty(); }
        std::vector<std::string> getRefNames() const { return m_scopeCounter.getRefNames(); }
        std::map<std::string, int> getRefMap() const { return m_scopeCounter.getRefMap(); }
    private:
        std::shared_ptr<KVDBSpace> m_spHandler;
        RefCounter m_scopeCounter;
    };

private:
    std::map<std::string, std::shared_ptr<KVDBHandlerInstance>> m_mapInstances;
    IKVDBHandlerManager* m_handleManager { nullptr };
    std::mutex m_mutex;
};

} // namespace kvdbManager

#endif // _KVDBHANDLERCOLLECTION_H
