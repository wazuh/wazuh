#ifndef _KVDB_HANDLER_H
#define _KVDB_HANDLER_H

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <kvdb/ikvdbhandler.hpp>

namespace kvdbStore
{

using KVMap = std::unordered_map<std::string, json::Json>;

class KVDBHandler final : public IKVDBHandler
{
public:
    explicit KVDBHandler(std::shared_ptr<const KVMap> map) noexcept;
    ~KVDBHandler() override = default;

    // Non-copyable / non-movable
    KVDBHandler(const KVDBHandler&) = delete;
    KVDBHandler& operator=(const KVDBHandler&) = delete;
    KVDBHandler(KVDBHandler&&) = delete;
    KVDBHandler& operator=(KVDBHandler&&) = delete;

    // IKVDBHandler
    const json::Json& get(const std::string& key) const override;
    bool contains(const std::string& key) const noexcept override;

private:
    std::shared_ptr<const KVMap> m_map;
};

} // namespace kvdbStore

#endif // _KVDB_HANDLER_H
