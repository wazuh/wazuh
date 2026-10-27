/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 * GPLv2.
 */

#include <gtest/gtest.h>

#include "container_baseline_fim.h"
#include "container_baseline_fim_bridge.h"
extern "C"
{
#include "container_baseline_host_api.h"
}
#include "db.h"
#include <cstdarg>
#include <json.hpp>
#include <map>
#include <string>
#include <vector>

extern "C" void container_reporting_test_host(int limit);
extern "C" void container_reporting_test_row_limit(int limit);

namespace
{
    std::map<std::string, bool> admission;
    std::map<std::string, std::vector<std::string>> files;
    std::map<std::string, std::string> contexts;
    std::vector<std::pair<std::string, int>> persisted;
    std::vector<std::string> warnings;
    bool listed = false;
    bool connector_available = true;
    bool reject_persistence = false;
    bool fail_distinct_ids = false;
    int distinct_id_queries = 0;
    bool fail_txn_start = false;
    int file_size = 1;

    class ContainerReportingTest : public testing::Test
    {
        protected:
            void SetUp() override
            {
                admission = {{"a", true}, {"b", true}};
                files.clear();
                contexts.clear();
                persisted.clear();
                warnings.clear();
                listed = false;
                connector_available = true;
                reject_persistence = false;
                fail_distinct_ids = false;
                distinct_id_queries = 0;
                fail_txn_start = false;
                file_size = 1;
                fim_db_init(FIM_DB_MEMORY, [](modules_log_level_t, const char*) {}, 1000, 0, nullptr);
                fim_container_doc_budget_release("a");
                fim_container_doc_budget_release("b");
                fim_container_doc_budget_release("c");
                container_reporting_test_host(1);
            }

            void TearDown() override
            {
                fim_db_teardown();
            }

            static int syncFlag(const char* container, const char* path)
            {
                const std::string filter = std::string("WHERE container_id='") + container + "' AND path='" + path + "'";
                cJSON* rows = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, filter.c_str());
                EXPECT_NE(rows, nullptr);
                const cJSON* value = cJSON_GetObjectItem(cJSON_GetArrayItem(rows, 0), "sync");
                const int flag = cJSON_IsNumber(value) ? value->valueint : -1;
                cJSON_Delete(rows);
                return flag;
            }
    };
} // namespace

extern "C" bool container_reporting_test_persist(const char* id, int operation, int sync_flag)
{
    if (reject_persistence)
        return false;

    if (sync_flag)
        persisted.emplace_back(id, operation);

    return true;
}

extern "C" void __wrap__mdebug1(const char*, int, const char*, const char*, ...) {}
extern "C" void __wrap__minfo(const char*, int, const char*, const char*, ...) {}
extern "C" void __wrap__merror(const char*, int, const char*, const char*, ...) {}
extern "C" void __wrap__mwarn(const char*, int, const char*, const char* format, ...)
{
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    warnings.emplace_back(message);
}

extern "C" int __wrap_fim_collect_container_monitored_paths(cb_monitored_path_t** paths, size_t* count)
{
    static cb_monitored_path_t path {};
    path.internal_path = "/etc";
    *paths = &path;
    *count = 1;
    return 0;
}

extern "C" cJSON* __real_fim_db_get_distinct_container_ids(const char* table_name);
extern "C" cJSON* __wrap_fim_db_get_distinct_container_ids(const char* table_name)
{
    ++distinct_id_queries;
    return fail_distinct_ids ? nullptr : __real_fim_db_get_distinct_container_ids(table_name);
}

extern "C" TXN_HANDLE __real_fim_db_transaction_start(const char* table, result_callback_t callback, void* ctx);
extern "C" TXN_HANDLE __wrap_fim_db_transaction_start(const char* table, result_callback_t callback, void* ctx)
{
    if (fail_txn_start && std::string(table).find("\"b\"") != std::string::npos)
        return nullptr;

    return __real_fim_db_transaction_start(table, callback, ctx);
}

extern "C" void __wrap_fim_free_container_monitored_paths(cb_monitored_path_t*) {}
extern "C" int __wrap_fim_container_baseline_available(const char*)
{
    return 1;
}

extern "C" int __wrap_cbaseline_list_containers(const char*, cb_container_id_sink_t sink, void* ctx)
{
    EXPECT_FALSE(listed) << "reuse the warm-up-guarded listing";
    listed = true;

    if (!connector_available)
        return -1;

    for (const auto& [id, admitted] : admission) sink(id.c_str(), admitted, ctx);

    return static_cast<int>(admission.size());
}

extern "C" int __wrap_cbaseline_list_containers_ex(const char* socket,
                                                   cb_container_id_sink_t sink,
                                                   void* ctx,
                                                   cb_known_container_id_sink_t knownSink,
                                                   void* knownCtx,
                                                   int* snapshotComplete)
{
    const int listed = __wrap_cbaseline_list_containers(socket, sink, ctx);

    if (listed >= 0)
    {
        for (const auto& [id, admitted] : admission)
        {
            static_cast<void>(admitted);

            if (knownSink != nullptr) knownSink(id.c_str(), knownCtx);
        }
    }

    if (snapshotComplete != nullptr) *snapshotComplete = listed >= 0 ? 1 : 0;

    return listed;
}

extern "C" int __wrap_cbaseline_run_fim_dbsync(const char*,
                                               const cb_monitored_path_t*,
                                               int,
                                               cb_dbsync_row_sink_t sink,
                                               cb_container_context_sink_t context_sink,
                                               cb_container_status_sink_t status,
                                               cb_rate_limit_fn,
                                               void* ctx)
{
    EXPECT_TRUE(listed) << "admission must precede the first stored row";

    for (const auto& [id, paths] : files)
    {
        auto [context, inserted] = contexts.try_emplace(
        id, nlohmann::json{{"container", {{"id", id}}}}.dump());
        static_cast<void>(inserted);
        context_sink(id.c_str(), context->second.c_str(), ctx);

        for (const auto& path : paths)
        {
            const nlohmann::json row = {{"container_id", id}, {"path", path}, {"version", 1}, {"size", file_size}};
            sink(id.c_str(), "file_entry", row.dump().c_str(), ctx);
        }

        cb_container_status_t result {};
        result.container_id = id.c_str();
        status(&result, ctx);
    }

    return static_cast<int>(files.size());
}

TEST_F(ContainerReportingTest, GrantedRowsSurviveModifyAndSendStatefulDeletes)
{
    files["a"] = {"/etc/one", "/etc/two"};
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("a", "/etc/two"), 0);
    ASSERT_EQ(fim_db_count_synced_container_docs("a"), 1);
    EXPECT_EQ(fim_db_count_synced_docs(FIMDB_FILE_TABLE_NAME), 0);
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("fim.container_file_limit"), std::string::npos);

    persisted.clear();
    file_size = 2;
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0].second, OPERATION_MODIFY);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("a", "/etc/two"), 0);

    persisted.clear();
    files["a"] = {"/etc/two"};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(persisted.size(), 2u);
    EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"a:/etc/one", OPERATION_DELETE}));
    EXPECT_EQ(persisted[1], (std::pair<std::string, int> {"a:/etc/two", OPERATION_CREATE}));
    EXPECT_EQ(syncFlag("a", "/etc/two"), 1) << "an unchanged withheld row must be promoted";
}

TEST_F(ContainerReportingTest, AdmissionRetractsRetainsAndRestoresUnchangedRows)
{
    for (const int limit :
            {
                1, 0
            })
    {
        container_reporting_test_host(limit);
        files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
        admission = {{"a", true}, {"b", true}};
        listed = false;
        fim_run_container_baseline();
        EXPECT_EQ(syncFlag("b", "/etc/one"), 1);

        persisted.clear();
        admission["b"] = false;
        listed = false;
        fim_run_container_baseline();
        ASSERT_EQ(persisted.size(), 1u);
        EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"b:/etc/one", OPERATION_DELETE}));
        EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
        EXPECT_EQ(syncFlag("b", "/etc/one"), 0);

        persisted.clear();
        admission["b"] = true;
        listed = false;
        fim_run_container_baseline();
        ASSERT_EQ(persisted.size(), 1u);
        EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"b:/etc/one", OPERATION_CREATE}));
        EXPECT_EQ(syncFlag("b", "/etc/one"), 1);
    }

}

TEST_F(ContainerReportingTest, IncrementalAdmissionUpdateDoesNotQueryAllFileRows)
{
    const char* initialAdmission[] {"a"};
    fim_container_set_admitted(initialAdmission, 1);
    const int queriesAfterReconcile = distinct_id_queries;
    ASSERT_GT(queriesAfterReconcile, 0);

    fim_container_update_admitted("b", 1);
    EXPECT_TRUE(fim_container_is_admitted("b"));
    EXPECT_EQ(queriesAfterReconcile, distinct_id_queries)
            << "a lifecycle addition must not trigger the full distinct-container scan";

    fim_container_update_admitted("a", 0);
    EXPECT_FALSE(fim_container_is_admitted("a"));
    EXPECT_EQ(queriesAfterReconcile, distinct_id_queries);
}

TEST_F(ContainerReportingTest, FirstScanWithholdsAndUnavailableConnectorKeepsRows)
{
    admission = {{"a", true}, {"b", false}};
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    fim_run_container_baseline();
    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0].first, "a:/etc/one");
    EXPECT_EQ(syncFlag("b", "/etc/one"), 0);

    connector_available = false;
    listed = false;
    persisted.clear();
    files.clear();
    fim_run_container_baseline();
    EXPECT_TRUE(persisted.empty());
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
}

TEST_F(ContainerReportingTest, RestartSeedsBudgetFromStoredContainerFlags)
{
    files["a"] = {"/etc/one"};
    fim_run_container_baseline();
    fim_container_doc_budget_release("a");
    files["a"].push_back("/etc/two");
    persisted.clear();
    listed = false;
    fim_run_container_baseline();
    EXPECT_TRUE(persisted.empty());
    EXPECT_EQ(syncFlag("a", "/etc/two"), 0);
}

TEST_F(ContainerReportingTest, PersistenceFailureDoesNotMarkRowsAsReported)
{
    reject_persistence = true;
    files["a"] = {"/etc/one"};
    fim_run_container_baseline();
    EXPECT_EQ(syncFlag("a", "/etc/one"), 0);
    reject_persistence = false;
    listed = false;
    fim_run_container_baseline();
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
}

TEST_F(ContainerReportingTest, WithheldDeletesDoNotReachManagerWithUnlimitedDocumentBudget)
{
    container_reporting_test_host(0);
    admission["b"] = false;
    files["b"] = {"/etc/one"};
    fim_run_container_baseline();
    EXPECT_EQ(syncFlag("b", "/etc/one"), 0);
    persisted.clear();
    files["b"].clear();
    listed = false;
    fim_run_container_baseline();
    EXPECT_TRUE(persisted.empty());
}

TEST_F(ContainerReportingTest, AContainerDiscoveredDuringTheWalkIsNotSwept)
{
    files["c"] = {"/etc/one"};
    fim_run_container_baseline();
    EXPECT_EQ(syncFlag("c", "/etc/one"), 0);
}

TEST_F(ContainerReportingTest, RowCeilingHoldsAcrossCappedPassesAndFreesVanishedSlots)
{
    container_reporting_test_host(0);
    container_reporting_test_row_limit(2);
    files["a"] = {"/etc/b", "/etc/c", "/etc/d"};
    fim_run_container_baseline();
    EXPECT_EQ(fim_db_count_container_rows("a", nullptr), 2);
    EXPECT_EQ(fim_db_count_container_rows("a", "/etc/d"), 0);

    // A new file sorted before the cut used to displace nothing and add a row.
    files["a"].insert(files["a"].begin(), "/etc/a");
    persisted.clear();
    listed = false;
    fim_run_container_baseline();
    EXPECT_EQ(fim_db_count_container_rows("a", nullptr), 2);
    EXPECT_EQ(fim_db_count_container_rows("a", "/etc/a"), 0);
    EXPECT_TRUE(persisted.empty()) << "refreshing stored rows reports nothing";

    // The cap bit, yet delete detection still ran: the vanished file is retracted.
    files["a"] = {"/etc/a", "/etc/c", "/etc/d"};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"a:/etc/b", OPERATION_DELETE}));
    EXPECT_EQ(fim_db_count_container_rows("a", nullptr), 1);

    persisted.clear();
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"a:/etc/a", OPERATION_CREATE}));
    EXPECT_EQ(fim_db_count_container_rows("a", nullptr), 2);
}

TEST_F(ContainerReportingTest, ContextIsPreservedAndUpdatedAcrossReconciles)
{
    files["a"] = {"/etc/one"};
    fim_run_container_baseline();
    cJSON* block = fim_db_get_container_context("a");
    ASSERT_NE(nullptr, block);
    EXPECT_STREQ("a", cJSON_GetStringValue(cJSON_GetObjectItem(block, "id")));
    cJSON_Delete(block);

    listed = false;
    fim_run_container_baseline();
    block = fim_db_get_container_context("a");
    ASSERT_NE(nullptr, block);
    EXPECT_STREQ("a", cJSON_GetStringValue(cJSON_GetObjectItem(block, "id")));
    cJSON_Delete(block);

    contexts["a"] = R"({"container":{"id":"a","labels":{"revision":"2"}}})";
    listed = false;
    fim_run_container_baseline();
    block = fim_db_get_container_context("a");
    ASSERT_NE(nullptr, block);
    const cJSON* labels = cJSON_GetObjectItem(block, "labels");
    EXPECT_STREQ("2", cJSON_GetStringValue(cJSON_GetObjectItem(labels, "revision")));
    cJSON_Delete(block);
}

namespace
{
    bool warned(const char* fragment)
    {
        for (const auto& warning : warnings)
        {
            if (warning.find(fragment) != std::string::npos)
                return true;
        }

        return false;
    }

    bool hasContext(const char* container)
    {
        fim_db_clear_container_contexts();
        cJSON* block = fim_db_get_container_context(container);
        const bool present = block != nullptr;
        cJSON_Delete(block);
        return present;
    }
} // namespace

TEST_F(ContainerReportingTest, UnreadableContainerIdsSkipThePruneToo)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    fim_run_container_baseline();
    ASSERT_EQ(fim_db_set_container_context("b", R"({"container":{"id":"b"}})"), FIMDB_OK);

    // b leaves, but its rows cannot be enumerated: pruning its context against
    // the live list would strand rows whose DELETEs need it.
    admission.erase("b");
    files.erase("b");
    fail_distinct_ids = true;
    listed = false;
    fim_run_container_baseline();

    EXPECT_TRUE(warned("could not read container ids"));
    EXPECT_EQ(fim_db_count_container_rows("b", nullptr), 1);
    EXPECT_TRUE(hasContext("b"));

    fail_distinct_ids = false;
    listed = false;
    fim_run_container_baseline();
    EXPECT_EQ(fim_db_count_container_rows("b", nullptr), 0);
    EXPECT_FALSE(hasContext("b"));
}

TEST_F(ContainerReportingTest, FailedSweepKeepsTheContextUntilARetrySucceeds)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    fim_run_container_baseline();
    ASSERT_EQ(fim_db_set_container_context("b", R"({"container":{"id":"b"}})"), FIMDB_OK);

    admission.erase("b");
    files.erase("b");
    fail_txn_start = true;
    listed = false;
    fim_run_container_baseline();

    EXPECT_TRUE(warned("could not confirm the rows of removed container 'b'"));
    EXPECT_EQ(fim_db_count_container_rows("b", nullptr), 1);
    EXPECT_TRUE(hasContext("b")) << "the prune must keep an unswept container's context";

    fail_txn_start = false;
    persisted.clear();
    listed = false;
    fim_run_container_baseline();
    EXPECT_EQ(fim_db_count_container_rows("b", nullptr), 0);
    EXPECT_FALSE(hasContext("b"));
    EXPECT_TRUE(persisted.empty()) << "the departure already retracted b's document";
}

TEST_F(ContainerReportingTest, AnUnregisteredHostStillReleasesTheRow)
{
    // The row is owned by fim_persist_baseline_row on every path; this one
    // leaked it. LeakSanitizer or Valgrind is what fails on a regression.
    fim_container_baseline_set_host_api(nullptr);
    EXPECT_EQ(fim_persist_baseline_row("a:/etc/one", OPERATION_CREATE, "idx", cJSON_CreateObject(), 1), -1);
    EXPECT_TRUE(persisted.empty());
}
