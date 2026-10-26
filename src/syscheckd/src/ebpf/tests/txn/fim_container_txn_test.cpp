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

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
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
            case INSERTED:
                ++g_inserted;
                break;

            case MODIFIED:
                ++g_modified;

                if (payload != nullptr && cJSON_GetObjectItem(payload, "new") != nullptr &&
                        cJSON_GetObjectItem(payload, "old") != nullptr)
                {
                    ++g_modified_wrapped;
                }

                break;

            case DELETED:
                ++g_deleted;
                break;

            default:
                ++g_unexpected;
                break;
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
                      "{\"path\":\"%s\",\"container_id\":\"%s\",\"mode\":0,"
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
                      "{\"path\":\"%s\",\"container_id\":\"%s\",\"mode\":0,"
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

    /* Case 8 needs to know what the context looked like AT THE MOMENT each DELETE
     * callback ran, not afterwards, so it is read from inside the callback. */
    std::string g_context_container;
    int g_context_seen_during_delete = 0;
    int g_context_missing_during_delete = 0;

    void DeleteWatchingCallback(ReturnTypeCallback type, const cJSON* payload, void* user)
    {
        RowCallback(type, payload, user);

        if (type == DELETED)
        {
            cJSON* ctx = fim_db_get_container_context(g_context_container.c_str());

            if (ctx != nullptr)
            {
                ++g_context_seen_during_delete;
                cJSON_Delete(ctx);
            }
            else
            {
                ++g_context_missing_during_delete;
            }
        }
    }

    /* What the sweep does to one container, in the order container_baseline_fim.cpp
     * does it (SweepOneContainer): rows and their DELETE events first, the context
     * only once those have been served. */
    void SweepOneContainer(const char* containerId, callback_txn_t callback)
    {
        const auto scope = TxnScope(containerId);
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), callback, nullptr);
        fim_db_transaction_deleted_rows(txn, callback, nullptr);
        fim_db_delete_container_context(containerId);
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

    /* 8. D23's ordering, as an assertion rather than a comment. A container's
     *    DELETE events are built from its stored context, so the context has
     *    to outlive them: SweepOneContainer() deletes the rows, lets their
     *    callbacks run, and only then drops the context. Reversing those two
     *    lines produces deletes that cannot say what they refer to, and
     *    nothing else in the tree would notice. */
    {
        ResetCounters();
        g_context_container = "cid-sweep";
        g_context_seen_during_delete = 0;
        g_context_missing_during_delete = 0;

        const auto scope = TxnScope("cid-sweep");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-sweep", 0, 4);
        fim_db_transaction_close(txn);
        fim_db_set_container_context("cid-sweep", "{\"container\":{\"id\":\"cid-sweep\"}}");

        ResetCounters();
        SweepOneContainer("cid-sweep", DeleteWatchingCallback);

        std::snprintf(detail,
                      sizeof(detail),
                      "DELETED=%d with context=%d without=%d",
                      g_deleted,
                      g_context_seen_during_delete,
                      g_context_missing_during_delete);
        ok &= Check("the context outlives the deletes built from it",
                    g_deleted == 4 && g_context_seen_during_delete == 4 && g_context_missing_during_delete == 0,
                    detail);

        cJSON* after = fim_db_get_container_context("cid-sweep");
        std::snprintf(detail, sizeof(detail), "context after sweep=%s", after == nullptr ? "gone" : "present");
        ok &= Check("... and is gone once they have been served", after == nullptr, detail);
        cJSON_Delete(after);
    }

    /* 9. Sweeping the same container again is a no-op. The removal hook and
     *    the periodic floor can both reach the same container -- a removal
     *    notification arriving just before a scheduled pass is the ordinary
     *    case, not a rare race -- so the second one must produce no events and
     *    no error rather than a second round of DELETEs. */
    {
        ResetCounters();
        SweepOneContainer("cid-sweep", RowCallback);

        std::snprintf(detail,
                      sizeof(detail),
                      "DELETED=%d INSERTED=%d MODIFIED=%d (want 0/0/0)",
                      g_deleted,
                      g_inserted,
                      g_modified);
        ok &= Check("sweeping an already swept container does nothing",
                    g_deleted == 0 && g_inserted == 0 && g_modified == 0 && g_unexpected == 0,
                    detail);
    }

    /* 10. D11 rule 2: a single-container sweep has no authoritative view of
     *     what else exists, so it may not touch anything outside its own
     *     scope. The per-container path deliberately does not prune. */
    {
        ResetCounters();
        fim_db_set_container_context("cid-keep", "{\"container\":{\"id\":\"cid-keep\"}}");
        fim_db_set_container_context("cid-drop", "{\"container\":{\"id\":\"cid-drop\"}}");

        const auto scope = TxnScope("cid-keep");
        TXN_HANDLE txn = fim_db_transaction_start(scope.c_str(), RowCallback, nullptr);
        SyncPaths(txn, "cid-keep", 0, 2);
        fim_db_transaction_close(txn);

        SweepOneContainer("cid-drop", RowCallback);

        cJSON* keep = fim_db_get_container_context("cid-keep");
        cJSON* drop = fim_db_get_container_context("cid-drop");
        std::snprintf(detail,
                      sizeof(detail),
                      "cid-keep=%s cid-drop=%s",
                      keep == nullptr ? "gone" : "present",
                      drop == nullptr ? "gone" : "present");
        ok &= Check("one container's sweep leaves another's context alone", keep != nullptr && drop == nullptr, detail);
        cJSON_Delete(keep);
        cJSON_Delete(drop);
    }

    /* 11. The prune, which is the whole-node pass's half of the same job: a
     *     context whose sweep was interrupted between deleting the rows and
     *     deleting the context is orphaned, and nothing else would ever
     *     collect it. Only a pass holding an authoritative list may do this,
     *     which is why it is here and not in case 10. */
    {
        fim_db_set_container_context("cid-orphan", "{\"container\":{\"id\":\"cid-orphan\"}}");

        const char* keep_list[] = {"cid-keep"};
        fim_db_prune_container_contexts(keep_list, 1);

        cJSON* orphan = fim_db_get_container_context("cid-orphan");
        cJSON* keep = fim_db_get_container_context("cid-keep");
        std::snprintf(detail,
                      sizeof(detail),
                      "cid-orphan=%s cid-keep=%s",
                      orphan == nullptr ? "gone" : "present",
                      keep == nullptr ? "gone" : "present");
        ok &=
            Check("the prune collects an orphan and keeps the live one", orphan == nullptr && keep != nullptr, detail);
        cJSON_Delete(orphan);
        cJSON_Delete(keep);
    }

    /* 12. A cold read races the writers that free cached blocks. The miss path
     *     used to cache the block, release the lock and only then duplicate it,
     *     so a concurrent clear() or set() could free it first. Run under
     *     Valgrind for the use-after-free itself; without it this still proves
     *     every read returns a whole, owned block. */
    {
        constexpr int kRounds = 2000;
        fim_db_set_container_context("cid-race", "{\"container\":{\"id\":\"cid-race\"}}");

        std::atomic<bool> stop {false};
        std::thread writer(
            [&stop]()
            {
                while (!stop.load())
                {
                    fim_db_clear_container_contexts();
                    fim_db_set_container_context("cid-race", "{\"container\":{\"id\":\"cid-race\"}}");
                }
            });

        int malformed = 0;

        for (int i = 0; i < kRounds; ++i)
        {
            fim_db_clear_container_contexts();
            cJSON* block = fim_db_get_container_context("cid-race");
            const char* id = cJSON_GetStringValue(cJSON_GetObjectItem(block, "id"));

            if (block == nullptr || id == nullptr || std::strcmp(id, "cid-race") != 0)
            {
                ++malformed;
            }

            cJSON_Delete(block);
        }

        stop = true;
        writer.join();

        std::snprintf(detail, sizeof(detail), "malformed=%d of %d", malformed, kRounds);
        ok &= Check("a cold read survives concurrent cache writers", malformed == 0, detail);
    }

    /* 13. A write the database never attempted is not a stored context. Last,
     *     because it tears the database down. */
    {
        fim_db_teardown();
        const int stored = fim_db_set_container_context("cid-late", "{\"container\":{\"id\":\"cid-late\"}}");
        cJSON* late = fim_db_get_container_context("cid-late");
        std::snprintf(detail,
                      sizeof(detail),
                      "set=%s cached=%s",
                      stored == FIMDB_OK ? "OK" : "ERR",
                      late == nullptr ? "no" : "yes");
        ok &= Check("a write after teardown fails and is not cached", stored != FIMDB_OK && late == nullptr, detail);
        cJSON_Delete(late);
    }

    std::printf("\n%s\n", ok ? "ALL OK" : "FAILURES");
    return ok ? 0 : 1;
}
