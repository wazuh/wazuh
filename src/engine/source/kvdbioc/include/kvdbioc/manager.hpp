#ifndef _KVDBIOC_MANAGER_HPP
#define _KVDBIOC_MANAGER_HPP

#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>

#include <rocksdb/db.h>

#include <kvdbioc/iManager.hpp>

namespace kvdb
{
class DbHandle;

class KVDBManager final : public IKVDBManager
{
public:
    explicit KVDBManager(std::filesystem::path rootDir);
    ~KVDBManager() override;

    void add(std::string_view name) override;

    void put(std::string_view name, std::string_view key, std::string_view value) override;

    void hotSwap(std::string_view name) override;

    std::shared_ptr<IReadOnlyKVDBHandler> openReadOnly(std::string_view name) override;

    void remove(std::string_view name) override;

private:
    std::filesystem::path makeNextInstancePath(std::string_view name);

    std::filesystem::path m_root;
    mutable std::shared_mutex m_mutex;  // Allows concurrent readers
    std::unordered_map<std::string, std::shared_ptr<DbHandle>> m_handles;
};

} // namespace kvdb

#endif // _KVDBIOC_MANAGER_HPP
