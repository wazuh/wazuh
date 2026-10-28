/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 * GPLv2.
 */

#include <gtest/gtest.h>

#include "container_baseline_fim.h"
#include "container_baseline_fim_bridge.h"
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
    std::vector<std::pair<std::string, int>> persisted;
    std::vector<std::string> warnings;
    bool listed = false;
    bool connector_available = true;
    bool reject_persistence = false;
    int file_size = 1;

    class ContainerReportingTest : public testing::Test
    {
        protected:
            void SetUp() override
            {
                admission = {{"a", true}, {"b", true}};
                files.clear();
                persisted.clear();
                warnings.clear();
                listed = false;
                connector_available = true;
                reject_persistence = false;
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

extern "C" int __wrap_cbaseline_run_fim_dbsync(const char*,
                                               const cb_monitored_path_t*,
                                               int,
                                               cb_dbsync_row_sink_t sink,
                                               cb_container_status_sink_t status,
                                               cb_rate_limit_fn,
                                               void* ctx)
{
    EXPECT_TRUE(listed) << "admission must precede the first stored row";

    for (const auto& [id, paths] : files)
    {
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

// A container the listing refused and a container the listing never saw both read
// as "may not report", and used to be indistinguishable: one set held both. They
// need opposite treatment -- the refused one stays withheld, the unseen one means
// the snapshot predates it and has to be retaken -- so the distinction is pinned
// here. Without it a container started after the agent is silent for the life of
// the process, under the default configuration.
TEST_F(ContainerReportingTest, AdmissionTellsARefusedContainerFromAnUnknownOne)
{
    admission = {{"a", true}, {"b", false}};
    files["a"] = {"/etc/one"};
    files["b"] = {"/etc/one"};
    fim_run_container_baseline();

    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0) << "the cap refused it";
    EXPECT_EQ(fim_container_is_admitted("c"), 0);

    EXPECT_EQ(fim_container_admission_is_stale("a"), 0);
    EXPECT_EQ(fim_container_admission_is_stale("b"), 0) << "refused is not unknown: do not re-ask";
    EXPECT_NE(fim_container_admission_is_stale("c"), 0) << "created after the snapshot: re-ask";
}

// A failed listing must not install an empty snapshot, or every container would
// read as unknown and re-ask on every batch.
TEST_F(ContainerReportingTest, AFailedListingLeavesTheAdmissionSnapshotAlone)
{
    admission = {{"a", true}, {"b", false}};
    files["a"] = {"/etc/one"};
    fim_run_container_baseline();
    ASSERT_EQ(fim_container_admission_is_stale("b"), 0);

    connector_available = false;
    listed = false;
    fim_run_container_baseline();

    EXPECT_NE(fim_container_is_admitted("a"), 0) << "the previous answer stands";
    EXPECT_EQ(fim_container_admission_is_stale("b"), 0) << "the previous answer stands";
}
