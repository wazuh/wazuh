#include "reconcile/sqlite_prior_state_store.hpp"

#include <filesystem>
#include <stdexcept>

#include <sqlite3.h>

namespace wazuh::container_baseline {

namespace {

constexpr auto kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS prior_row(
    id           TEXT PRIMARY KEY,
    container_id TEXT NOT NULL,
    idx          TEXT NOT NULL,
    content_hash INTEGER NOT NULL,
    version      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_prior_container ON prior_row(container_id);
)SQL";

void Exec(sqlite3* db, const char* sql)
{
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK)
    {
        const std::string message = err ? err : "unknown sqlite error";
        sqlite3_free(err);
        throw std::runtime_error("prior-state store: " + message);
    }
}

// content_hash / version are conceptually uint64 but SQLite integers are signed
// 64-bit; round-trip the bits unchanged.
sqlite3_int64 ToSigned(std::uint64_t value)
{
    return static_cast<sqlite3_int64>(value);
}

std::uint64_t ToUnsigned(sqlite3_int64 value)
{
    return static_cast<std::uint64_t>(value);
}

} // namespace

SqlitePriorStateStore::SqlitePriorStateStore(const std::string& db_path)
{
    // Ensure the parent directory exists — sqlite3_open creates the file but not
    // the path. Skipped for ":memory:" (no parent). Best-effort: a genuinely bad
    // path still fails loudly at open() below.
    if (const std::filesystem::path path {db_path}; path.has_parent_path())
    {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
    }

    if (sqlite3_open(db_path.c_str(), &m_db) != SQLITE_OK)
    {
        const std::string message = m_db ? sqlite3_errmsg(m_db) : "open failed";
        sqlite3_close(m_db);
        m_db = nullptr;
        throw std::runtime_error("prior-state store: " + message);
    }
    Exec(m_db, kSchema);
}

SqlitePriorStateStore::~SqlitePriorStateStore()
{
    sqlite3_close(m_db);
}

FingerprintMap SqlitePriorStateStore::load(const std::string& container_id)
{
    FingerprintMap out;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, idx, content_hash, version FROM prior_row WHERE container_id = ?;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
    }
    sqlite3_bind_text(stmt, 1, container_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const auto* id  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const auto* idx = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        RowFingerprint fp;
        fp.index        = idx ? idx : "";
        fp.content_hash = ToUnsigned(sqlite3_column_int64(stmt, 2));
        fp.version      = ToUnsigned(sqlite3_column_int64(stmt, 3));
        out.emplace(id ? id : "", std::move(fp));
    }
    sqlite3_finalize(stmt);
    return out;
}

std::vector<std::string> SqlitePriorStateStore::knownContainerIds()
{
    std::vector<std::string> out;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT DISTINCT container_id FROM prior_row;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
    }
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const auto* id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        out.emplace_back(id ? id : "");
    }
    sqlite3_finalize(stmt);
    return out;
}

std::unordered_map<std::string, std::size_t> SqlitePriorStateStore::countByIndex()
{
    std::unordered_map<std::string, std::size_t> out;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT idx, COUNT(*) FROM prior_row GROUP BY idx;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
    }
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const auto* idx = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        out.emplace(idx ? idx : "", static_cast<std::size_t>(sqlite3_column_int64(stmt, 1)));
    }
    sqlite3_finalize(stmt);
    return out;
}

void SqlitePriorStateStore::applyDelta(const std::string& container_id, const RowDelta& delta)
{
    Exec(m_db, "BEGIN;");
    try
    {
        sqlite3_stmt* upsert = nullptr;
        const char* upsertSql =
            "INSERT OR REPLACE INTO prior_row(id, container_id, idx, content_hash, version) VALUES(?,?,?,?,?);";
        if (sqlite3_prepare_v2(m_db, upsertSql, -1, &upsert, nullptr) != SQLITE_OK)
        {
            throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
        }

        const auto storeRow = [&](const EmittedRow& row) {
            sqlite3_reset(upsert);
            sqlite3_bind_text(upsert, 1, row.id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(upsert, 2, container_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(upsert, 3, row.index.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(upsert, 4, ToSigned(contentHash(row.json)));
            sqlite3_bind_int64(upsert, 5, ToSigned(row.version));
            if (sqlite3_step(upsert) != SQLITE_DONE)
            {
                throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
            }
        };
        for (const auto& row : delta.creates)  storeRow(row);
        for (const auto& row : delta.modifies) storeRow(row);
        sqlite3_finalize(upsert);

        sqlite3_stmt* remove = nullptr;
        if (sqlite3_prepare_v2(m_db, "DELETE FROM prior_row WHERE id = ?;", -1, &remove, nullptr) != SQLITE_OK)
        {
            throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
        }
        for (const auto& ref : delta.deletes)
        {
            sqlite3_reset(remove);
            sqlite3_bind_text(remove, 1, ref.id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(remove) != SQLITE_DONE)
            {
                throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
            }
        }
        sqlite3_finalize(remove);

        Exec(m_db, "COMMIT;");
    }
    catch (...)
    {
        Exec(m_db, "ROLLBACK;");
        throw;
    }
}

void SqlitePriorStateStore::purgeContainer(const std::string& container_id)
{
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, "DELETE FROM prior_row WHERE container_id = ?;", -1, &stmt, nullptr) != SQLITE_OK)
    {
        throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
    }
    sqlite3_bind_text(stmt, 1, container_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        sqlite3_finalize(stmt);
        throw std::runtime_error(std::string {"prior-state store: "} + sqlite3_errmsg(m_db));
    }
    sqlite3_finalize(stmt);
}

} // namespace wazuh::container_baseline
