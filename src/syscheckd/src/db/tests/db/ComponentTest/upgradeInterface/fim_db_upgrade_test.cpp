/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstdio>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <sqlite3.h>

#include "dbsync.hpp"
#include "fimDB.hpp"
#include "fimDBSpecialization.h"
#include "legacyFimSchemaV1.hpp"

/*
 * A released 5.0.0 agent's fim.db has no container_id anywhere, and
 * file_entry's key is (path). The container work makes it
 * (container_id, path), which SQLite cannot do in place on a WITHOUT ROWID
 * table -- so file_entry is rebuilt, and these tests are what say the rebuild
 * keeps what the agent was holding.
 *
 * Nothing here goes through DB::init: that hardcodes the real on-disk path.
 * The DBSync handle is built directly, with the same create statement and the
 * same upgrade list the module uses.
 */

namespace
{
    constexpr auto UPGRADE_DB_PATH {"fim_upgrade_test.db"};
    constexpr auto FRESH_DB_PATH {"fim_fresh_test.db"};

    int readUserVersion(const char* path)
    {
        sqlite3* db = nullptr;

        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        {
            if (db)
            {
                sqlite3_close(db);
            }

            return -1;
        }

        sqlite3_stmt* stmt = nullptr;
        int version = -1;

        if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, nullptr) == SQLITE_OK &&
                sqlite3_step(stmt) == SQLITE_ROW)
        {
            version = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return version;
    }

    /// One column of the first row of `query`, as text.
    std::string scalar(const char* path, const std::string& query)
    {
        sqlite3* db = nullptr;

        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        {
            if (db)
            {
                sqlite3_close(db);
            }

            return "<unreadable>";
        }

        sqlite3_stmt* stmt = nullptr;
        std::string out {"<none>"};

        if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK &&
                sqlite3_step(stmt) == SQLITE_ROW)
        {
            const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            out = (text != nullptr ? text : "<null>");
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return out;
    }

    /// See the matching helper in the syscollector suite: whitespace runs are
    /// collapsed so reindenting a DDL literal does not read as a schema change,
    /// but identifier quoting is left alone on purpose, because a quoted table
    /// name is the fingerprint of a create-then-rename rebuild.
    std::string schemaFingerprint(const char* path)
    {
        const auto raw = scalar(path,
                                "SELECT group_concat(type || '|' || name || '|' || tbl_name || '|' || "
                                "COALESCE(sql, ''), x'0a') FROM (SELECT * FROM sqlite_master "
                                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name);");

        std::string collapsed;
        bool inSpace = false;

        for (const auto character : raw)
        {
            const bool isSpace = (character == ' ' || character == '\t' || character == '\r');

            if (isSpace)
            {
                inSpace = true;
                continue;
            }

            if (inSpace)
            {
                collapsed += ' ';
                inSpace = false;
            }

            collapsed += character;
        }

        return collapsed;
    }

    void execOrFail(const char* path, const std::string& sql)
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr), SQLITE_OK);
        char* errMsg = nullptr;
        const auto rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
        const std::string message {errMsg ? errMsg : ""};

        if (errMsg)
        {
            sqlite3_free(errMsg);
        }

        sqlite3_close(db);
        ASSERT_EQ(rc, SQLITE_OK) << message;
    }

    /// A fim.db exactly as released 5.0.0 left it, holding two rows.
    ///
    /// db_status_field_dm is added to file_entry but not to table_metadata,
    /// which is what a live agent looks like: SQLiteDBEngine adds the column
    /// lazily, per table, on first use in a transaction.
    void seedLegacyV1Database(const char* path)
    {
        std::string schema {LEGACY_FIM_V1_SCHEMA};
        schema += "ALTER TABLE file_entry ADD COLUMN db_status_field_dm INTEGER DEFAULT 1;";
        schema += "INSERT INTO file_entry (path, checksum, device, inode, size, mtime, version) "
                  "VALUES ('/etc/passwd', 'host-sum', 2049, 131, 1234, 1700000000, 7);";
        // A row with NULLs in non-key columns: the rebuild names every column,
        // and a mis-ordered list would land values in the wrong ones.
        schema += "INSERT INTO file_entry (path, checksum) VALUES ('/etc/shadow', 'shadow-sum');";
        schema += "PRAGMA user_version = 1;";
        execOrFail(path, schema);
    }

    /// Opens the database the way DB::init does, which is what runs the upgrade.
    void openThroughDbSync(const char* path)
    {
        DBSync dbSync(HostType::AGENT,
                      DbEngineType::SQLITE3,
                      path,
                      FIMDBCreator<OS_TYPE>::CreateStatement(),
                      DbManagement::PERSISTENT,
                      fimDbUpgradeStatements());
    }

    class FimDbUpgradeTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                std::remove(UPGRADE_DB_PATH);
                std::remove(FRESH_DB_PATH);
            }

            void TearDown() override
            {
                std::remove(UPGRADE_DB_PATH);
                std::remove(FRESH_DB_PATH);
            }
    };
}

TEST_F(FimDbUpgradeTest, AReleasedDatabaseIsUpgradedWithoutLosingWhatItHeld)
{
    seedLegacyV1Database(UPGRADE_DB_PATH);

    ASSERT_EQ(readUserVersion(UPGRADE_DB_PATH), 1) << "precondition: a version-1 database";
    ASSERT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT count(*) FROM pragma_table_info('file_entry') WHERE name = 'container_id';"),
              "0") << "precondition: a released 5.0.0 file_entry has no container_id";

    openThroughDbSync(UPGRADE_DB_PATH);

    EXPECT_EQ(readUserVersion(UPGRADE_DB_PATH), 3) << "the upgrade must advance the recorded version";
    EXPECT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='container_context';"),
              "1");

    // container_id has to lead the key, not merely exist.
    EXPECT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT group_concat(name) FROM (SELECT name FROM pragma_table_info('file_entry') "
                     "WHERE pk > 0 ORDER BY pk);"),
              "container_id,path");

    // Per-transaction state; SQLiteDBEngine adds it back on first use.
    EXPECT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT count(*) FROM pragma_table_info('file_entry') WHERE name = 'db_status_field_dm';"),
              "0") << "the status column survived the rebuild";

    EXPECT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT count(*) FROM sqlite_master WHERE name LIKE '%_upgrade_v%_old';"),
              "0") << "the rebuild left its scratch table behind";

    // Rows keep their checksums and their versions. A changed checksum would
    // resync the agent's whole file inventory; a reset version would make the
    // indexer noop the document it already holds.
    EXPECT_EQ(scalar(UPGRADE_DB_PATH, "SELECT count(*) FROM file_entry;"), "2");
    // Two leading slashes: container_id is '' for a host row and the path
    // itself begins with one.
    EXPECT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT container_id || '/' || path || '/' || checksum || '/' || version || '/' || "
                     "device || '/' || inode FROM file_entry WHERE path = '/etc/passwd';"),
              "//etc/passwd/host-sum/7/2049/131");
    EXPECT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT device IS NULL AND inode IS NULL FROM file_entry WHERE path = '/etc/shadow';"),
              "1") << "a NULL was filled in, so the copy shifted a column";

    EXPECT_EQ(scalar(UPGRADE_DB_PATH, "PRAGMA integrity_check;"), "ok");
}

TEST_F(FimDbUpgradeTest, TheRebuiltTableKeepsBothItsIndexes)
{
    // The trap this ordering exists to avoid: ALTER TABLE ... RENAME carries
    // path_index and inode_index along with the old table, keeping their names.
    // A CREATE INDEX issued while the old table still exists finds the name
    // taken, IF NOT EXISTS makes it a silent no-op, and DROP TABLE then takes
    // the only real indexes with it -- leaving file_entry unindexed, with no
    // error anywhere, and every path lookup a full scan.
    seedLegacyV1Database(UPGRADE_DB_PATH);
    openThroughDbSync(UPGRADE_DB_PATH);

    EXPECT_EQ(scalar(UPGRADE_DB_PATH,
                     "SELECT group_concat(name) FROM (SELECT name FROM sqlite_master WHERE type='index' "
                     "AND tbl_name='file_entry' AND name NOT LIKE 'sqlite_%' ORDER BY name);"),
              "inode_index,path_index");
}

TEST_F(FimDbUpgradeTest, AContainerRowNoLongerCollidesWithTheHostRow)
{
    seedLegacyV1Database(UPGRADE_DB_PATH);
    openThroughDbSync(UPGRADE_DB_PATH);

    execOrFail(UPGRADE_DB_PATH,
               "INSERT INTO file_entry (container_id, path, checksum) "
               "VALUES ('c1', '/etc/passwd', 'ctr-sum');");

    EXPECT_EQ(scalar(UPGRADE_DB_PATH, "SELECT count(*) FROM file_entry WHERE path = '/etc/passwd';"), "2")
            << "the host and container rows for the same path must coexist";
}

TEST_F(FimDbUpgradeTest, AContainerScopedTransactionWorksOnAMigratedDatabase)
{
    // Container teardown and the scheduled reconcile both open a transaction
    // scoped to container_id. validatedScopeColumn() throws when the column is
    // absent, and the throw is swallowed twice on the way out, so on an
    // un-migrated database the sweep is a silent no-op behind a debug line.
    // This is what says the migration removed that condition.
    seedLegacyV1Database(UPGRADE_DB_PATH);
    openThroughDbSync(UPGRADE_DB_PATH);

    DBSync dbSync(HostType::AGENT,
                  DbEngineType::SQLITE3,
                  UPGRADE_DB_PATH,
                  FIMDBCreator<OS_TYPE>::CreateStatement(),
                  DbManagement::PERSISTENT,
                  fimDbUpgradeStatements());

    const auto txnJson = nlohmann::json::parse(
                             R"({"tables":["file_entry"],"scope":{"column":"container_id","value":"c1"}})");

    EXPECT_NO_THROW(
    {
        DBSyncTxn txn(dbSync.handle(), txnJson, 0, 100,
                      [](ReturnTypeCallback, const nlohmann::json&) {});
    }) << "a container-scoped transaction must be possible once container_id exists";
}

TEST_F(FimDbUpgradeTest, AMigratedDatabaseHasTheSchemaOfAFreshOne)
{
    // Nothing in the code keeps CreateStatement() and fimDbUpgradeStatements()
    // converging; this test is the only thing that does. An edit to a DDL
    // constant changes the created side and not the migrated one, and the only
    // way back to green is to append a migration entry making the same change
    // to a database that already exists.
    openThroughDbSync(FRESH_DB_PATH);

    seedLegacyV1Database(UPGRADE_DB_PATH);
    openThroughDbSync(UPGRADE_DB_PATH);

    EXPECT_EQ(readUserVersion(FRESH_DB_PATH), readUserVersion(UPGRADE_DB_PATH));
    EXPECT_EQ(schemaFingerprint(FRESH_DB_PATH), schemaFingerprint(UPGRADE_DB_PATH))
            << "a migrated database and a freshly created one must be the same database";
}

namespace
{
    /// Opens the database like openThroughDbSync and returns why DBSync recreated it, if it did.
    std::string openAndGetRecreateReason(const char* path)
    {
        DBSync dbSync(HostType::AGENT,
                      DbEngineType::SQLITE3,
                      path,
                      FIMDBCreator<OS_TYPE>::CreateStatement(),
                      DbManagement::PERSISTENT,
                      fimDbUpgradeStatements());
        return dbSync.recreateReason();
    }

    /// A development fim.db that already had container_id in file_entry's key
    /// but was stamped at an older version, so the v2 -> v3 rebuild runs on it.
    void seedDevelopmentDatabase(const char* path, const std::string& rows)
    {
        std::string schema {FIMDBCreator<OS_TYPE>::CreateStatement()};
        schema += rows;
        schema += "PRAGMA user_version = 2;";
        execOrFail(path, schema);
    }
}

TEST_F(FimDbUpgradeTest, ADevelopmentDatabaseWithCollidingKeysIsRecreatedInsteadOfDisablingFim)
{
    seedDevelopmentDatabase(UPGRADE_DB_PATH,
                            "INSERT INTO file_entry (container_id, path, checksum) VALUES ('', '/etc/passwd', 'h');"
                            "INSERT INTO file_entry (container_id, path, checksum) VALUES ('cid', '/etc/passwd', 'c');");

    std::string reason;
    ASSERT_NO_THROW(reason = openAndGetRecreateReason(UPGRADE_DB_PATH));

    EXPECT_NE(reason.find("could not be upgraded from version 2"), std::string::npos) << reason;
    EXPECT_EQ(readUserVersion(UPGRADE_DB_PATH), 3);
    EXPECT_EQ(scalar(UPGRADE_DB_PATH, "SELECT count(*) FROM file_entry;"), "0");
    EXPECT_EQ(schemaFingerprint(UPGRADE_DB_PATH), [&]()
    {
        openThroughDbSync(FRESH_DB_PATH);
        return schemaFingerprint(FRESH_DB_PATH);
    }());
}

TEST_F(FimDbUpgradeTest, ADevelopmentContainerRowIsNeverTurnedIntoAHostRow)
{
    seedDevelopmentDatabase(UPGRADE_DB_PATH,
                            "INSERT INTO file_entry (container_id, path, checksum) VALUES ('cid', '/etc/hosts', 'c');");

    std::string reason;
    ASSERT_NO_THROW(reason = openAndGetRecreateReason(UPGRADE_DB_PATH));

    EXPECT_FALSE(reason.empty()) << "the guard must reject the rebuild, not copy the row as a host row";
    EXPECT_EQ(readUserVersion(UPGRADE_DB_PATH), 3);
    EXPECT_EQ(scalar(UPGRADE_DB_PATH, "SELECT count(*) FROM file_entry WHERE container_id = '';"), "0");
}

TEST_F(FimDbUpgradeTest, ADatabaseFromANewerVersionIsRecreated)
{
    seedLegacyV1Database(UPGRADE_DB_PATH);
    execOrFail(UPGRADE_DB_PATH, "PRAGMA user_version = 9;");

    std::string reason;
    ASSERT_NO_THROW(reason = openAndGetRecreateReason(UPGRADE_DB_PATH));

    EXPECT_NE(reason.find("written by a newer version"), std::string::npos) << reason;
    EXPECT_EQ(readUserVersion(UPGRADE_DB_PATH), 3);
    EXPECT_EQ(scalar(UPGRADE_DB_PATH, "SELECT count(*) FROM file_entry;"), "0");
}
