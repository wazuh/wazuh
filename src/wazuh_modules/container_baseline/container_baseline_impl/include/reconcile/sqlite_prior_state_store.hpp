#pragma once

#include <string>
#include <vector>

#include "reconcile/i_prior_state_store.hpp"

struct sqlite3;

namespace wazuh::container_baseline {

/// @brief SQLite-backed prior-state store. One flat table (`prior_row`) keyed by
/// row id, indexed by container id. Uses the vendored sqlite3 the module already
/// links (contra dbsync: this is a 4-column cache, not the inventory pipeline).
/// Pass ":memory:" for tests.
class SqlitePriorStateStore final : public IPriorStateStore
{
public:
    explicit SqlitePriorStateStore(const std::string& db_path);
    ~SqlitePriorStateStore() override;

    SqlitePriorStateStore(const SqlitePriorStateStore&)            = delete;
    SqlitePriorStateStore& operator=(const SqlitePriorStateStore&) = delete;

    [[nodiscard]] FingerprintMap load(const std::string& container_id) override;
    [[nodiscard]] std::vector<std::string> knownContainerIds() override;
    [[nodiscard]] std::unordered_map<std::string, std::size_t> countByIndex() override;
    void applyDelta(const std::string& container_id, const RowDelta& delta) override;
    void purgeContainer(const std::string& container_id) override;

private:
    sqlite3* m_db{nullptr};
};

} // namespace wazuh::container_baseline
