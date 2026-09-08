/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Pins what the container FIM consumers assume about a *scoped* `file_entry`
 * transaction — and, in case 7, about the non-transactional upsert that
 * replaces it on the path-reconcile path — against the real libfimdb, not a
 * test double.
 * Every other container test in this tree stands libfimdb in with an in-memory
 * store carrying DBSync's callback shape, which by construction cannot show
 * any of these:
 *
 *  1. `fim_db_transaction_close()` without `fim_db_transaction_deleted_rows()`
 *     still delivers every row callback. This is the path D15 forces on a path
 *     reconcile (`may_detect_deletions == false`), so if closing dropped the
 *     queued results the reconcile would silently persist nothing. The spike
 *     branch's `container_live_fim.cpp` asserts the opposite — "without this
 *     call ... only persisted 1-2 of several hundred synced rows" — and
 *     `catch_up_container_baseline()` calls `deleted_rows` on a transaction
 *     that has nothing to sweep purely to get that flush. Case 1 says the
 *     flush is not needed; see 12 §12.14.
 *  2. `container_id` is really part of the primary key: the same paths under a
 *     second container are new rows, not an update of the first container's.
 *  3. A scoped `deleted_rows` sweep deletes exactly the untouched rows *in
 *     that scope*.
 *  4. ... and leaves every other container's rows alone. This is the property
 *     the per-container transaction model, C15's fix and the whole
 *     stopped-vs-gone distinction rest on.
 *
 * Deliberately plain C++ with a hand-rolled harness rather than gtest, for the
 * same reason as the eBPF Module's contract tests: it has to be runnable
 * wherever the tree builds, and `TEST=yes` cannot currently configure in every
 * environment (see 09's environment notes). Run with `make check` in this
 * directory; it needs a built `libfimdb.so` and writes nothing to disk
 * (FIM_DB_MEMORY).
 */

#include <cstdio>
#include <string>
#include <vector>

#include <cJSON.h>

#include "db.h"
#include "fimCommonDefs.h"

namespace
{

int g_inserted = 0;
int g_modified = 0;
int g_deleted = 0;
int g_unexpected = 0;
/* MODIFIED payloads that arrived as {"old":...,"new":...} rather than a bare
 * updated row. The container callback reads the changed columns out of "old",
 * so this is the difference between an alert and silence. */
int g_modified_wrapped = 0;

void ResetCounters()
{
    g_inserted = g_modified = g_deleted = g_unexpected = 0;
    g_modified_wrapped = 0;
}

void LogCallback(modules_log_level_t, const char* message)
{
    // libfimdb logs schema/statement errors here. Anything arriving during this
    // test is a failure signal worth seeing, so it is not swallowed.
    std::fprintf(stderr, "[fimdb] %s\n", message);
}

void RowCallback(ReturnTypeCallback type, const cJSON* payload, void*)
{
    switch (type)
    {
        case INSERTED: ++g_inserted; break;
        case MODIFIED:
            ++g_modified;

            if (payload != nullptr && cJSON_GetObjectItem(payload, "new") != nullptr &&
                cJSON_GetObjectItem(payload, "old") != nullptr)
            {
                ++g_modified_wrapped;
            }

            break;
        case DELETED:  ++g_deleted;  break;
        default:       ++g_unexpected; break;
    }
}

/* A row in the dbsync column format both container consumers emit. Only the
 * columns that matter here carry meaningful values; `checksum` is NOT NULL in
 * the schema, so it always has to be present. */
std::string RowJson(const char* containerId, const char* path)
{
    char buffer[1024];
    std::snprintf(buffer,
                  sizeof(buffer),
                  "{\"path\":\"%s\",\"container_id\":\"%s\",\"container_json\":\"\",\"mode\":0,"
                  "\"size\":1,\"permissions\":\"0644\",\"uid\":\"0\",\"gid\":\"0\",\"owner\":\"root\","
                  "\"group\":\"root\",\"inode\":1,\"device\":1,\"mtime\":1,\"hash_md5\":\"\","
                  "\"hash_sha1\":\"\",\"hash_sha256\":\"\",\"checksum\":\"cs\",\"version\":1}",
                  path,
                  containerId);
    return buffer;
}

/* The same row with a different size and checksum, i.e. what re-reading a file
 * that changed on disk produces. */
std::string ChangedRowJson(const char* containerId, const char* path)
{
    char buffer[1024];
    std::snprintf(buffer,
                  sizeof(buffer),
                  "{\"path\":\"%s\",\"container_id\":\"%s\",\"container_json\":\"\",\"mode\":0,"
                  "\"size\":99,\"permissions\":\"0644\",\"uid\":\"0\",\"gid\":\"0\",\"owner\":\"root\","
                  "\"group\":\"root\",\"inode\":1,\"device\":1,\"mtime\":2,\"hash_md5\":\"\","
                  "\"hash_sha1\":\"\",\"hash_sha256\":\"\",\"checksum\":\"cs-changed\",\"version\":1}",
                  path,
                  containerId);
    return buffer;
}

/* The same scoped-transaction JSON `container_baseline_fim.cpp` builds, with
 * FIMDB_FILE_CONTAINER_ID_COLUMN as the scope column. */
std::string TxnScope(const char* containerId)
{
    return std::string("{\"tables\":[\"file_entry\"],\"scope\":{\"column\":\"") + FIMDB_FILE_CONTAINER_ID_COLUMN +
           "\",\"value\":\"" + containerId + "\"}}";
}

void SyncPaths(TXN_HANDLE txn, const char* containerId, int first, int last)
{
    for (int i = first; i < last; ++i)
    {
        char path[64];
        std::snprintf(path, sizeof(path), "/etc/a%d", i);
        fim_db_transaction_sync_row_json(txn, "file_entry", RowJson(containerId, path).c_str());
    }
}

bool Check(const char* name, bool condition, const char* detail)
{
    std::printf("%-46s %-34s %s\n", name, detail, condition ? "OK" : "*** FAILED ***");
    return condition;
}

constexpr int kContainerARows = 500;
constexpr int kContainerBRows = 10;
constexpr int kContainerAReported = 5;

} // namespace

int main()
{
    if (fim_db_init(FIM_DB_MEMORY, LogCallback, 100000, 100000, nullptr) != FIMDB_OK)
    {
        std::fprintf(stderr, "fim_db_init failed\n");
        return 1;
    }

    bool ok = true;
    char detail[128];

    /* 1. Closing without deleted_rows must not lose a single row callback. */
    {
        ResetCounters();
        const auto scope = TxnScope("cid-a");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);

        if (txn == nullptr)
        {
            std::fprintf(stderr, "fim_db_transaction_start failed\n");
            return 1;
        }

        SyncPaths(txn, "cid-a", 0, kContainerARows);
        fim_db_transaction_close(txn);

        std::snprintf(detail, sizeof(detail), "INSERTED=%d (want %d)", g_inserted, kContainerARows);
        ok &= Check("close() without deleted_rows keeps every row", g_inserted == kContainerARows && g_unexpected == 0, detail);
    }

    /* 2. The same paths under a second container are new rows: container_id is
     *    part of the primary key (69303187cd's schema change, against the real
     *    schema rather than a stand-in). */
    {
        ResetCounters();
        const auto scope = TxnScope("cid-b");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-b", 0, kContainerBRows);
        fim_db_transaction_close(txn);

        std::snprintf(detail, sizeof(detail), "INSERTED=%d MODIFIED=%d", g_inserted, g_modified);
        ok &= Check("container_id is part of the primary key", g_inserted == kContainerBRows && g_modified == 0, detail);
    }

    /* 3. A scoped sweep deletes exactly the untouched rows in that scope. */
    {
        ResetCounters();
        const auto scope = TxnScope("cid-a");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-a", 0, kContainerAReported);
        fim_db_transaction_deleted_rows(txn, RowCallback, nullptr);

        const int expected = kContainerARows - kContainerAReported;
        std::snprintf(detail, sizeof(detail), "DELETED=%d (want %d)", g_deleted, expected);
        ok &= Check("deleted_rows sweeps only its own scope", g_deleted == expected, detail);
    }

    /* 4. ... and the other container's rows survived it. Re-reporting them must
     *    produce no INSERTED, which it would if the sweep had removed them. */
    {
        ResetCounters();
        const auto scope = TxnScope("cid-b");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-b", 0, kContainerBRows);
        fim_db_transaction_close(txn);

        std::snprintf(detail, sizeof(detail), "INSERTED=%d (want 0)", g_inserted);
        ok &= Check("another container's rows survive that sweep", g_inserted == 0, detail);
    }

    /* 5. A changed row must be reported as MODIFIED, and the payload must be
     *    the {"old","new"} pair. fim_db_transaction_sync_row_json() has to ask
     *    DBSync for it ("return_old_data"); without that option DBSync hands
     *    the callback a bare updated row, container_txn_callback() finds no
     *    "new" member and returns, and every modification to an
     *    already-known container file is dropped. Invisibly, too: the row
     *    still converges in file_entry, so only the missing alert shows it. */
    {
        ResetCounters();
        const auto scope = TxnScope("cid-c");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-c", 0, 3);
        fim_db_transaction_close(txn);

        ResetCounters();
        txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);

        for (int i = 0; i < 3; ++i)
        {
            char path[64];
            std::snprintf(path, sizeof(path), "/etc/a%d", i);
            fim_db_transaction_sync_row_json(txn, "file_entry", ChangedRowJson("cid-c", path).c_str());
        }

        fim_db_transaction_close(txn);

        std::snprintf(detail, sizeof(detail), "MODIFIED=%d wrapped=%d (want 3/3)", g_modified, g_modified_wrapped);
        ok &= Check("a changed row reports MODIFIED with old+new", g_modified == 3 && g_modified_wrapped == 3, detail);
    }

    /* 6. What close() actually does to the rows this transaction did not
     *    refresh: it DELETES them. DBSyncImplementation::closeTransaction()
     *    runs deleteRowsByStatusField() unconditionally, so "close instead of
     *    deleted_rows" suppresses the DELETED *callbacks* and nothing else —
     *    the rows are gone either way. A path reconcile re-reads a handful of
     *    named files by design (D15), so on that path this wipes the rest of
     *    the container's FIM state and the next full baseline re-reports it
     *    all as added. Pinned here because the behaviour is the opposite of
     *    what a reader expects from the name. */
    {
        ResetCounters();
        const auto scope = TxnScope("cid-c");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-c", 0, 1); // refresh 1 of the 3 stored rows
        fim_db_transaction_close(txn);

        ResetCounters();
        txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-c", 0, 3);
        fim_db_transaction_close(txn);

        std::snprintf(detail, sizeof(detail), "INSERTED=%d (want 2)", g_inserted);
        ok &= Check("close() still deletes the rows it did not refresh", g_inserted == 2, detail);
    }

    /* 7. D18's fix for case 6: the non-transactional per-row upsert a path
     *    reconcile uses instead. It must report a change as MODIFIED with the
     *    {"old","new"} pair, and — the whole point — leave the rows it did not
     *    touch alone. Re-reporting them afterwards must produce no INSERTED,
     *    which is exactly the assertion case 6 fails. */
    {
        ResetCounters();
        const auto scope = TxnScope("cid-d");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-d", 0, 3);
        fim_db_transaction_deleted_rows(txn, RowCallback, nullptr);

        /* Change exactly one of the three, outside any transaction. */
        ResetCounters();
        fim_db_container_file_sync(ChangedRowJson("cid-d", "/etc/a0").c_str(), RowCallback, nullptr);

        std::snprintf(detail, sizeof(detail), "MODIFIED=%d wrapped=%d (want 1/1)", g_modified, g_modified_wrapped);
        ok &= Check("direct upsert reports MODIFIED with old+new", g_modified == 1 && g_modified_wrapped == 1, detail);

        /* The other two must still be there: re-reporting all three yields no
         * INSERTED at all. Under case 6's transaction this is 2. */
        ResetCounters();
        txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-d", 0, 3);
        fim_db_transaction_close(txn);

        std::snprintf(detail, sizeof(detail), "INSERTED=%d (want 0)", g_inserted);
        ok &= Check("direct upsert leaves untouched rows in place", g_inserted == 0, detail);
    }

    std::printf("\n%s\n", ok ? "ALL OK" : "FAILURES");
    return ok ? 0 : 1;
}
