#ifndef _KVDB_HANDLER_H
#define _KVDB_HANDLER_H

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <kvdbstore/ikvdbhandler.hpp>

namespace kvdbstore
{

using KVMap = std::unordered_map<std::string, json::Json>;

/**
 * @brief Holds the source document (allocator owner) and the extracted member entries.
 *
 * Member entries are created via extractObjectMembers() (zero-copy swap), so their
 * string data references the sourceDoc's allocator. sourceDoc MUST be declared before
 * entries to ensure it is destroyed AFTER entries (reverse declaration order).
 */
struct KVMapStore
{
    json::Json sourceDoc; ///< Keeps allocator alive for swapped entries' string data.
    KVMap entries;        ///< Values swapped from sourceDoc (zero-copy).
};

class KVDBHandler final : public IKVDBHandler
{
public:
    explicit KVDBHandler(std::shared_ptr<const KVMapStore> store) noexcept;
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
    std::shared_ptr<const KVMapStore> m_store;
};

} // namespace kvdbstore

#endif // _KVDB_HANDLER_H
