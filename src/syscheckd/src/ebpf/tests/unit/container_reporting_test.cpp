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
#include "container_event_drain.hpp"
#include "rt_engine.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <cstdarg>
#include <thread>
#include <json.hpp>
#include <map>
#include <string>
#include <vector>

extern "C" void container_reporting_test_host(int limit);
extern "C" void container_reporting_test_row_limit(int limit);
extern "C" void container_reporting_test_frequency(int frequency);
extern "C" void container_reporting_test_shutdown(bool value);
extern "C" int container_reporting_test_scan_trylock(void);
extern "C" void container_reporting_test_scan_unlock(void);

/* Defined in container_baseline_fim.cpp under WAZUH_UNIT_TESTING: the drain's own
 * reconcile handler, which has internal linkage there. */
void fim_container_reconcile_batch_for_testing(const fim_container_events::ReconcileRequest& request);

namespace
{
    std::map<std::string, bool> admission;

    /* Run inside the wrapped walk, while fim_run_container_baseline() holds the
     * transaction lock. Only AReportedRemovalWaitsForAWalkHoldingTheLock sets it. */
    std::function<void()> inside_walk;
    std::map<std::string, std::vector<std::string>> files;
    std::map<std::string, std::string> contexts;
    std::vector<std::pair<std::string, int>> persisted;
    std::vector<std::string> warnings;
    bool listed = false;
    bool connector_available = true;
    int pending_replies = 0;
    std::size_t baseline_walks = 0;
    std::atomic<std::size_t> admission_list_requests {0};
    std::atomic<std::size_t> resolver_list_requests {0};
    std::function<std::string()> drain_reply_provider;

    const std::string pending_reply =
        "{\"status\":\"ok\",\"containers\":[],\"admission_pending\":true}\n";
    const std::string settled_reply =
        "{\"status\":\"ok\",\"containers\":[{\"container_id\":\"a\",\"cgroup_id\":1,\"synced\":true},"
        "{\"container_id\":\"b\",\"cgroup_id\":2,\"synced\":false}],\"complete\":true}\n";

    bool waitFor(const std::function<bool()>& ready, std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;

        while (!ready())
        {
            if (std::chrono::steady_clock::now() >= deadline) return false;

            std::this_thread::sleep_for(std::chrono::milliseconds {10});
        }

        return true;
    }

    std::string drain_socket_path;
    std::string drain_list_reply;
    int drain_reply_fd = -1;
    std::function<void()> on_listing_reply;

    fim_container_events::DrainConfig resolverConfig()
    {
        fim_container_events::DrainConfig config;
        config.connector_socket_path = "/tmp/fim-admission-resolver-test";
        config.resolver_interval_ms = 10;
        drain_socket_path = config.connector_socket_path;
        return config;
    }

    /* Whether the hooked listing claims to be the whole node. True is the
     * ordinary case; false models container_instances still resolving. */
    bool list_complete = true;
    bool sources_pending = false;

    /* Containers the hooked connector knows of but cannot key. */
    std::set<std::string> unkeyed;
    bool unkeyed_known = true;

    /* Which of those the cap refused. The connector ranks them like any other
     * container, so the shim reports each one's decision through the id sink;
     * empty means it admitted them all, which is the ordinary case. */
    std::set<std::string> unkeyed_refused;
    bool reject_persistence = false;

    /* Makes the sync-column write fail while persistence keeps succeeding. The
     * row is then offered, accepted by the manager -- and still left at sync=1,
     * which is a document the agent believes it withdrew and has not. */
    bool reject_sync_flag_write = false;

    /* How many SELECT DISTINCT container_id over file_entry one operation
     * costs. The query walks every FIM row on the node, so the count is the
     * point, not an implementation detail. */
    std::size_t distinct_id_queries = 0;

    /* Makes that query answer with a cJSON OBJECT instead of an array, which is
     * what a malformed reply looks like. cJSON_ArrayForEach() walks an object's
     * members just as happily, so the shape has to be checked rather than
     * assumed. */
    bool distinct_ids_malformed = false;
    std::size_t persist_attempts = 0;

    /* Makes that query fail outright, which is a different thing from answering
     * a malformed shape: the sweep then knows nothing about which containers
     * hold rows. */
    bool fail_distinct_ids = false;

    /* Makes container b's sweep transaction fail to open, so its rows survive a
     * sweep that believed it removed them. */
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
                pending_replies = 0;
                baseline_walks = 0;
                inside_walk = {};
                admission_list_requests = 0;
                resolver_list_requests = 0;
                drain_reply_provider = {};
                drain_socket_path.clear();
                drain_list_reply.clear();
                drain_reply_fd = -1;
                on_listing_reply = {};
                list_complete = true;
                sources_pending = false;
                unkeyed.clear();
                unkeyed_known = true;
                unkeyed_refused.clear();
                reject_persistence = false;
                reject_sync_flag_write = false;
                distinct_id_queries = 0;
                distinct_ids_malformed = false;
                persist_attempts = 0;
                fail_distinct_ids = false;
                fail_txn_start = false;
                file_size = 1;
                fim_db_init(FIM_DB_MEMORY, [](modules_log_level_t, const char*) {}, 1000, 0, nullptr);
                fim_container_doc_budget_release("a");
                fim_container_doc_budget_release("b");
                fim_container_doc_budget_release("c");
                container_reporting_test_host(1);
                fim_container_events::ContainerEventDrainTestPeer::reset();
            }

            void TearDown() override
            {
                fim_container_events_stop();
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
    /* Every OFFER, sent or withheld. `persisted` records only what the manager
     * would receive, which cannot tell a row that was refused from one that was
     * never read -- and that difference is the whole of the promotion skip. */
    ++persist_attempts;

    if (reject_persistence)
        return false;

    /* == 1, not truthiness: validate_and_persist_fim_event() sends only on
     * exactly 1, and the flag has negative values that mean "do not write the
     * column" rather than "report this". */
    if (sync_flag == 1)
        persisted.emplace_back(id, operation);

    return true;
}

extern "C" cJSON* __real_fim_db_get_distinct_container_ids(const char* table_name);

extern "C" cJSON* __wrap_fim_db_get_distinct_container_ids(const char* table_name)
{
    ++distinct_id_queries;

    if (fail_distinct_ids) return nullptr;

    if (distinct_ids_malformed)
    {
        /* Member VALUES that are real container ids, because
         * cJSON_GetStringValue() reads the value and not the name -- so an
         * unguarded walk of this object yields ids that exist and acts on
         * them. */
        cJSON* object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "first", "a");
        cJSON_AddStringToObject(object, "second", "b");
        return object;
    }

    return __real_fim_db_get_distinct_container_ids(table_name);
}

extern "C" int __real_fim_db_set_sync_flag(char* table_name, pending_sync_item_t* item, int sync_value);

extern "C" int __wrap_fim_db_set_sync_flag(char* table_name, pending_sync_item_t* item, int sync_value)
{
    if (reject_sync_flag_write)
        return -1;

    return __real_fim_db_set_sync_flag(table_name, item, sync_value);
}

// Successful list replies use the socket boundary so the real client parses
// them. With no scripted reply, connect reaches the real missing socket and
// exercises unavailability without requiring a listening socket or eBPF.
extern "C" int __real_connect(int fd, const sockaddr* address, socklen_t length);
extern "C" ssize_t __real_send(int fd, const void* buffer, size_t length, int flags);
extern "C" ssize_t __real_recv(int fd, void* buffer, size_t length, int flags);

extern "C" int __wrap_connect(int fd, const sockaddr* address, socklen_t length)
{
    drain_reply_fd = -1;

    if (address->sa_family == AF_UNIX && drain_reply_provider
            && drain_socket_path == reinterpret_cast<const sockaddr_un*>(address)->sun_path)
    {
        drain_list_reply = drain_reply_provider();
        ++resolver_list_requests;

        if (drain_list_reply.empty())
        {
            errno = ECONNREFUSED;
            return -1;
        }
    }

    if (address->sa_family == AF_UNIX && !drain_list_reply.empty()
            && drain_socket_path == reinterpret_cast<const sockaddr_un*>(address)->sun_path)
    {
        drain_reply_fd = fd;
        return 0;
    }

    return __real_connect(fd, address, length);
}

extern "C" ssize_t __wrap_send(int fd, const void* buffer, size_t length, int flags)
{
    return fd == drain_reply_fd ? static_cast<ssize_t>(length) : __real_send(fd, buffer, length, flags);
}

extern "C" ssize_t __wrap_recv(int fd, void* buffer, size_t length, int flags)
{
    if (fd != drain_reply_fd) return __real_recv(fd, buffer, length, flags);

    const auto count = std::min(length, drain_list_reply.size());
    std::memcpy(buffer, drain_list_reply.data(), count);
    drain_list_reply.erase(0, count);

    if (on_listing_reply)
    {
        auto callback = std::move(on_listing_reply);
        callback();
    }

    return static_cast<ssize_t>(count);
}

// Deterministic degraded startup, independent of the host's BPF installation.
extern "C" rt_handle_t __wrap_rt_open(const struct rt_filter*)
{
    return nullptr;
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

extern "C" int __wrap_cbaseline_list_containers_ex(const char*,
                                                   cb_container_id_sink_t sink,
                                                   void* ctx,
                                                   cb_list_status_t* out_status)
{
    ++admission_list_requests;
    EXPECT_TRUE(!listed || fim_container_admission_pending())
            << "reuse the warm-up-guarded listing outside admission retries";
    listed = true;

    /* A listing that failed says nothing about its own coverage, matching the
     * real shim. */
    if (out_status)
    {
        out_status->complete = 0;
        out_status->unkeyed_known = 0;
        out_status->admission_pending = 0;
        out_status->sources_pending = 0;
    }

    if (!connector_available)
        return -1;

    for (const auto& [id, admitted] : admission) sink(id.c_str(), admitted, ctx);

    if (unkeyed_known)
    {
        /* Exactly what the real shim does: the unkeyed ids go through the id
         * sink with the cap's decision, because the cap ranks them too. */
        for (const auto& id : unkeyed)
        {
            sink(id.c_str(), unkeyed_refused.count(id) == 0 ? 1 : 0, ctx);
        }
    }

    if (out_status)
    {
        /* A connector that reports WHICH containers it could not key cannot then
         * disagree with itself about whether any exist -- the real one derives
         * `withheld` from that very set. Derived here too, so no test can model
         * a server that cannot exist. */
        const bool complete = unkeyed_known ? unkeyed.empty() : list_complete;
        out_status->complete = complete && !sources_pending ? 1 : 0;
        out_status->unkeyed_known = unkeyed_known && !sources_pending ? 1 : 0;
        out_status->sources_pending = sources_pending ? 1 : 0;

        if (pending_replies > 0)
        {
            --pending_replies;
            out_status->admission_pending = 1;
            out_status->complete = 0;
            out_status->unkeyed_known = 0;
        }
    }

    if (on_listing_reply)
    {
        auto callback = std::move(on_listing_reply);
        callback();
    }

    return static_cast<int>(admission.size());
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
    ++baseline_walks;
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

    // After the rows, so the walk has done real work while it blocks.
    if (inside_walk) inside_walk();

    return static_cast<int>(files.size());
}

TEST_F(ContainerReportingTest, ASettledVerdictAppliesTheCapWhileAnotherSourceIsSilent)
{
    container_reporting_test_host(0);
    sources_pending = true;
    admission = {{"a", true}, {"b", false}};
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/two"}}};
    pending_replies = 1;
    fim_run_container_baseline();
    ASSERT_EQ(fim_container_admission_pending(), 1);
    EXPECT_TRUE(warnings.empty()) << "normal startup settlement is quiet";
    listed = false;
    fim_run_container_baseline();

    EXPECT_EQ(fim_container_admission_pending(), 0);
    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);
    EXPECT_EQ(persisted, (std::vector<std::pair<std::string, int>> {{"a:/etc/one", OPERATION_CREATE}}));
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("stale-container cleanup is not running"), std::string::npos);
    EXPECT_EQ(warnings[0].find("does not report"), std::string::npos) << "not an old connector";

    listed = false;
    fim_run_container_baseline();
    EXPECT_EQ(warnings.size(), 1u) << "a silent source must not warn on every pass";
}

TEST_F(ContainerReportingTest, ASilentSourcesOmittedContainersKeepTheirStoredReportingFlags)
{
    container_reporting_test_host(0);
    admission = {{"a", true}, {"b", true}, {"c", false}};
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/two"}}, {"c", {"/etc/three"}}};
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("b", "/etc/two"), 1);
    ASSERT_EQ(syncFlag("c", "/etc/three"), 0);

    // The available source refuses its named container. Neither stored flag
    // from the silent source may move just because that reply omits its ids.
    admission = {{"a", false}};
    files.clear();
    sources_pending = true;
    listed = false;
    persisted.clear();
    warnings.clear();
    fim_run_container_baseline();

    EXPECT_EQ(syncFlag("a", "/etc/one"), 0);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 1);
    EXPECT_EQ(syncFlag("c", "/etc/three"), 0);
    EXPECT_NE(fim_container_is_admitted("b"), 0);
    EXPECT_NE(fim_container_is_admitted("c"), 0);
    EXPECT_EQ(persisted, (std::vector<std::pair<std::string, int>> {{"a:/etc/one", OPERATION_DELETE}}));
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("stale-container cleanup is not running"), std::string::npos);

    const nlohmann::json withheld = {{"container_id", "c"}, {"path", "/etc/three"},
        {"version", 1}, {"sync", 0}, {"size", 1}
    };
    EXPECT_EQ(fim_persist_baseline_row("c:/etc/three", OPERATION_MODIFY, "wazuh-states-fim-files",
                                       cJSON_Parse(withheld.dump().c_str()), 1), 0)
            << "unknown admission must not promote an event-driven update either";
    EXPECT_EQ(persisted.size(), 1u);

    // Once enumeration is authoritative again, omission becomes a real
    // refusal. Installing that answer must release the temporary exception.
    const char* known[] = {"a"};
    fim_container_set_admission(known, 1, nullptr, 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);
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

TEST_F(ContainerReportingTest, RunTimeAdmissionPromotesAndDoesNotOnlyRetract)
{
    container_reporting_test_host(0);
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    admission = {{"a", true}, {"b", false}};
    listed = false;
    fim_run_container_baseline();
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/one"), 0) << "b is not admitted, so its row is withheld";

    // b gains admission BETWEEN baselines, which is the drain's path: it installs
    // the new set, and fim_container_set_admission() reconciles from there.
    //
    // That reconciliation used to retract and nothing else, so a container that
    // gained admission at run time -- one that started after the agent, or one
    // readmitted when another freed a slot under containers.synced_limit -- kept
    // its rows at sync=0 until the next whole-node baseline.
    persisted.clear();
    const char* known[] = {"a", "b"};
    const char* admitted[] = {"a", "b"};
    fim_container_set_admission(known, 2, admitted, 2);

    ASSERT_EQ(persisted.size(), 1u) << "the newly admitted container's row must be promoted now";
    EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"b:/etc/one", OPERATION_CREATE}));
    EXPECT_EQ(syncFlag("b", "/etc/one"), 1);

    // ...and the same path must still retract, which is all it used to do.
    persisted.clear();
    const char* onlyA[] = {"a"};
    fim_container_set_admission(known, 2, onlyA, 1);

    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"b:/etc/one", OPERATION_DELETE}));
    EXPECT_EQ(syncFlag("b", "/etc/one"), 0);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
}

TEST_F(ContainerReportingTest, AnUnadmittedContainersModificationNeverDemotesAReportedRow)
{
    container_reporting_test_host(0);

    // b is known but may not report. Admission now changes at run time from the
    // resolver thread, so a file event for b can land at any moment after this.
    const char* known[] = {"a", "b"};
    const char* onlyA[] = {"a"};
    fim_container_set_admission(known, 2, onlyA, 1);
    persisted.clear();

    // A row the manager ALREADY holds (sync=1), modified while b is withheld.
    // Writing 0 to its column here would be a 1 -> 0 with no DELETE behind it,
    // and updateContainerReporting() retracts by selecting sync=1 -- so the row
    // would drop out of the only query that could ever withdraw it.
    const char* reported = R"({"container_id":"b","path":"/etc/one","version":1,"size":1,"sync":1})";
    EXPECT_EQ(fim_persist_baseline_row("b:/etc/one", OPERATION_MODIFY, "wazuh-states-fim-files",
                                       cJSON_Parse(reported), 2),
              FIM_CONTAINER_SYNC_UNCHANGED)
            << "the stored column must be left for the retraction to find";
    EXPECT_TRUE(persisted.empty()) << "a withheld container still reports nothing";

    // A row the manager never had is plainly withheld, exactly as before.
    const char* unreported = R"({"container_id":"b","path":"/etc/two","version":1,"size":1,"sync":0})";
    EXPECT_EQ(
        fim_persist_baseline_row("b:/etc/two", OPERATION_MODIFY, "wazuh-states-fim-files", cJSON_Parse(unreported), 2),
        0)
            << "nothing is owed for a row the manager never saw";
    EXPECT_TRUE(persisted.empty());
}

TEST_F(ContainerReportingTest, APendingHoldReportsChangesToDocumentsTheManagerAlreadyHas)
{
    files["a"] = {"/etc/one"};
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);
    persisted.clear();

    // The next pass sees a changed reported document and a new document while
    // the connector is settling. Only the former belongs on the manager yet,
    // even with its per-container document budget already full.
    file_size = 2;
    files["a"].push_back("/etc/two");
    listed = false;
    pending_replies = 1;
    fim_run_container_baseline();

    ASSERT_EQ(fim_container_admission_pending(), 1);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("a", "/etc/two"), 0);
    EXPECT_EQ(persisted, (std::vector<std::pair<std::string, int>> {{"a:/etc/one", OPERATION_MODIFY}}));

    // Settlement has no replay for the sync=1 modification. It must already
    // have reached the manager; the unchanged row needs no further event.
    persisted.clear();
    const char* known[] = {"a"};
    fim_container_set_admission(known, 1, known, 1);
    EXPECT_TRUE(persisted.empty());
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("a", "/etc/two"), 0);
}

TEST_F(ContainerReportingTest, AnUnkeyableContainerKeepsItsFimStateWithoutBlockingCleanup)
{
    files = {{"a", {"/etc/one"}}, {"ghost", {"/etc/one"}}, {"unkeyed", {"/etc/one"}}};
    admission = {{"a", true}, {"ghost", true}, {"unkeyed", true}};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("ghost", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("unkeyed", "/etc/one"), 1);

    // ghost is gone. unkeyed is still running but the resolver cannot key it,
    // so the connector names it apart from the list. The sweep must delete the
    // first, keep the second, and RUN despite the list being partial.
    admission = {{"a", true}};
    files = {{"a", {"/etc/one"}}};
    unkeyed = {"unkeyed"};
    unkeyed_known = true;
    listed = false;
    fim_run_container_baseline();

    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("unkeyed", "/etc/one"), 1)
            << "a container nobody can key has not gone anywhere";
    EXPECT_EQ(syncFlag("ghost", "/etc/one"), -1)
            << "and it must not have kept the sweep from removing one that has";
}

// The cap bounds how many containers report, which is a question about ids and
// never about an attribution key. So a container the connector cannot key is
// ranked like any other, and its answer arrives the same way: in the admitted
// set, or absent from it.
//
// Treating it instead as unrankable -- admitting it because nothing had refused
// it -- is what let the node report past containers.synced_limit, and since a
// container is unkeyed for a while after every restart, that happened on every
// restart.
TEST_F(ContainerReportingTest, AContainerThatCannotBeKeyedIsRankedLikeAnyOther)
{
    // "stuck" and "spare" both lack a key. The connector admitted the first and
    // refused the second; the bridge must repeat both answers rather than
    // inventing one.
    const char* known[] = {"a", "b", "spare", "stuck"};
    const char* admitted[] = {"a", "stuck"};
    fim_container_set_admission(known, 4, admitted, 2);

    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0) << "the cap ranked it and said no";
    EXPECT_NE(fim_container_is_admitted("stuck"), 0) << "unkeyed, and the cap admitted it";
    EXPECT_EQ(fim_container_is_admitted("spare"), 0)
            << "unkeyed and refused: not being keyable is not a free pass past the cap";

    // And both are KNOWN, so a batch of their rows does not re-ask for a listing
    // that would answer the same way -- for a container that can never be
    // keyed, that is one listing per batch, for ever.
    EXPECT_EQ(fim_container_admission_is_stale("stuck"), 0);
    EXPECT_EQ(fim_container_admission_is_stale("spare"), 0);
    EXPECT_NE(fim_container_admission_is_stale("nobody"), 0) << "created after the snapshot: re-ask";
}

// End to end through the baseline, not just the predicate: a container the
// connector could not key and the cap turned down must not get its rows
// reported. The listing names it, so it survives the sweep -- withheld and
// deleted are opposite outcomes and the distinction has to hold for a container
// with no attribution key too.
TEST_F(ContainerReportingTest, ARefusedUnkeyedContainerIsWithheldButNotSweptAway)
{
    admission = {{"a", true}};
    unkeyed = {"spare"};
    unkeyed_refused = {"spare"};
    unkeyed_known = true;
    files = {{"a", {"/etc/one"}}, {"spare", {"/etc/one"}}};

    fim_run_container_baseline();

    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("spare", "/etc/one"), 0)
            << "the cap ranked it and said no; not being keyable is not a way round that";
    EXPECT_NE(syncFlag("spare", "/etc/one"), -1) << "and its row is still there: refused is not removed";

    // A DECIDED refusal, not an unheard-of container. The listing named it, so
    // the bridge has an answer for its next batch of rows; without that every
    // batch re-takes the listing to be told the same thing.
    EXPECT_EQ(fim_container_admission_is_stale("spare"), 0);
}

// The whole point of splitting the two questions apart. A container whose
// cgroup no process reports never resolves, so a listing that waits for every
// container to be keyed is never complete again -- the snapshot was installed
// once and then frozen, and every container that started afterwards was absent
// from it and read as refused for the life of the process.
TEST_F(ContainerReportingTest, AnUnkeyableContainerDoesNotFreezeAdmissionForTheWholeNode)
{
    files = {{"a", {"/etc/one"}}};
    admission = {{"a", true}};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);

    // From here on the node always holds one container nobody can key, so no
    // listing is ever complete again. "late" starts afterwards and the
    // connector admits it.
    files = {{"a", {"/etc/one"}}, {"late", {"/etc/one"}}};
    admission = {{"a", true}, {"late", true}};
    unkeyed = {"stuck"};
    unkeyed_known = true;
    listed = false;
    fim_run_container_baseline();

    EXPECT_NE(fim_container_is_admitted("late"), 0)
            << "the connector admitted it; a container nobody can key is no reason to refuse it";
    EXPECT_EQ(syncFlag("late", "/etc/one"), 1)
            << "a container that started after the unkeyable one must still reach the manager";
    EXPECT_EQ(fim_container_admission_is_stale("late"), 0) << "the snapshot was replaced, not frozen";
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

// A retraction that cannot be persisted leaves the document on the manager and
// the row at sync=1. That is the right state -- the next reconcile selects on
// exactly that and retries -- but until then the agent's integrity checksum
// covers content the manager does not have, and the repair is clearing and
// re-sending the whole FIM index. Said out loud, because an operator watching
// that happen has nothing else to connect it to.
TEST_F(ContainerReportingTest, AFailedRetractionIsReportedAndRetried)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    admission = {{"a", true}, {"b", true}};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);

    // b loses admission while persistence is refusing everything.
    warnings.clear();
    reject_persistence = true;
    const char* known[] = {"a", "b"};
    const char* onlyA[] = {"a"};
    fim_container_set_admission(known, 2, onlyA, 1);

    EXPECT_EQ(syncFlag("b", "/etc/one"), 1)
            << "the manager still holds the document, so the row must stay findable by the retraction";

    ASSERT_FALSE(warnings.empty()) << "a document left on the manager must not be silent";
    EXPECT_NE(warnings[0].find("could not withdraw"), std::string::npos);
    EXPECT_NE(warnings[0].find('b'), std::string::npos);

    // ...and the next reconcile finishes the job, because sync=1 is what it
    // selects on.
    warnings.clear();
    reject_persistence = false;
    persisted.clear();
    fim_container_set_admission(known, 2, onlyA, 1);

    EXPECT_EQ(syncFlag("b", "/etc/one"), 0);
    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0], (std::pair<std::string, int> {"b:/etc/one", OPERATION_DELETE}));
    EXPECT_TRUE(warnings.empty()) << "nothing is owed any more";
}

// A refused offer is not the only way a document is left on the manager, and it
// was the only one counted.
//
// The warning exists so an operator can connect a coming index resynchronisation
// to its cause, and the number in it is the whole of that signal. Counting only
// the refusals meant a row that would not serialise, a row with no path, or a
// sync-column write that failed all left a document behind and were reported as
// none -- the warning did not fire at all when every failure was of that kind.
// Counting down from the rows the query returned makes the number mean what it
// says: documents the manager still holds.
TEST_F(ContainerReportingTest, ARetractionThatIsNotRefusedButStillLeavesTheRowReportingIsCounted)
{
    // Room for both of b's documents, so two of them are owed a withdrawal and
    // the count has something to be wrong about.
    container_reporting_test_host(5);

    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one", "/etc/two"}}};
    admission = {{"a", true}, {"b", true}};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/two"), 1);

    // b loses admission. The manager ACCEPTS both withdrawals -- nothing is
    // refused -- but the column that records them cannot be written.
    warnings.clear();
    persisted.clear();
    reject_sync_flag_write = true;
    const char* known[] = {"a", "b"};
    const char* onlyA[] = {"a"};
    fim_container_set_admission(known, 2, onlyA, 1);

    EXPECT_EQ(syncFlag("b", "/etc/one"), 1) << "the column was not written, so the row still reports";
    EXPECT_EQ(syncFlag("b", "/etc/two"), 1);

    ASSERT_FALSE(warnings.empty()) << "two documents the agent believes it withdrew and has not";
    EXPECT_NE(warnings[0].find("could not withdraw 2 document(s)"), std::string::npos) << "got: " << warnings[0];

    // And it names what actually retries it. The drain's scheduled poll does
    // not: it installs an admission snapshot only when the view CHANGED, so a
    // poll that finds nothing new runs no reconcile.
    EXPECT_NE(warnings[0].find("next whole-node container baseline"), std::string::npos) << "got: " << warnings[0];

    // ...and the retry still works, because sync=1 is what the next reconcile
    // selects on.
    warnings.clear();
    reject_sync_flag_write = false;
    fim_container_set_admission(known, 2, onlyA, 1);

    EXPECT_EQ(syncFlag("b", "/etc/one"), 0);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);
    EXPECT_TRUE(warnings.empty()) << "nothing is owed any more";
}

// The retraction loop releases the document budget whatever happened, so a
// container whose rows stayed at sync=1 has its counter deleted while the
// manager still holds those documents. That looks like a way past the cap, and
// it is not: fim_container_doc_budget_release() drops a CACHE, and every path
// that spends budget calls fim_container_doc_budget_initialize() first, which
// recounts sync=1 rows straight from the database. An unretracted row is still
// sync=1, so it is still counted.
//
// Pinned because nothing else states it. The protection is one initialize call
// on each spending path, it is invisible from the release site, and removing
// the one in updateContainerReporting() lets this container report
// container_file_limit MORE documents on top of the ones already out there.
TEST_F(ContainerReportingTest, AFailedRetractionDoesNotHandBackTheBudgetItDidNotRecover)
{
    container_reporting_test_host(2);

    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one", "/etc/two"}}};
    admission = {{"a", true}, {"b", true}};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/two"), 1) << "b has spent both of its two documents";

    // b loses admission and NOTHING can be withdrawn. Both documents stay on
    // the manager; the budget is released anyway.
    reject_persistence = true;
    const char* known[] = {"a", "b"};
    const char* onlyA[] = {"a"};
    fim_container_set_admission(known, 2, onlyA, 1);
    reject_persistence = false;
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/two"), 1);

    // b is admitted again and has grown a third file.
    files["b"].push_back("/etc/three");
    admission = {{"a", true}, {"b", true}};
    listed = false;
    persisted.clear();
    fim_run_container_baseline();

    EXPECT_EQ(syncFlag("b", "/etc/three"), 0)
            << "b already holds two documents on the manager, which is its whole allowance";
}

// A whole-node baseline asked the database three separate times which
// containers hold FIM rows, and that query is a SELECT DISTINCT over every row
// on the node.
//
// One of the three is unavoidable: installing the admission snapshot at the top
// runs a reconcile before the walk, and the walk changes which containers have
// rows. The other two were adjacent -- the stale sweep read the ids, deleted
// some of them, and the promotion pass right after asked for the same list
// again. The sweep knows the answer, so it returns it.
TEST_F(ContainerReportingTest, AWholeNodeBaselineReadsTheContainerIdListTwiceNotThreeTimes)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    admission = {{"a", true}, {"b", true}};
    listed = false;
    distinct_id_queries = 0;

    fim_run_container_baseline();

    EXPECT_EQ(distinct_id_queries, 2u)
            << "one for the admission reconcile before the walk, one for the sweep after it";
}

// ...and the pass the sweep feeds still has to run. It is not a repeat of the
// reconcile at the top: the walk between them charges a container's DELETIONS
// to the same budget as its insertions, so a row withheld early because the
// budget was full becomes grantable once a later delete frees the slot, and
// nothing offers it again inside the walk.
TEST_F(ContainerReportingTest, ARowWithheldDuringTheWalkIsPromotedWhenADeleteFreesItsSlot)
{
    container_reporting_test_host(2);

    // Two files fill the budget exactly.
    files = {{"a", {"/etc/keep", "/etc/going"}}};
    admission = {{"a", true}};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/keep"), 1);
    ASSERT_EQ(syncFlag("a", "/etc/going"), 1);

    // /etc/going is removed and /etc/new appears in the same walk. The slot the
    // delete frees is what lets /etc/new report.
    files["a"] = {"/etc/keep", "/etc/new"};
    listed = false;
    fim_run_container_baseline();

    EXPECT_EQ(syncFlag("a", "/etc/keep"), 1);
    EXPECT_EQ(syncFlag("a", "/etc/new"), 1) << "the departed file's slot was freed in the same baseline";
}

// A reply that is not an array is not an empty node, and must not be read as a
// list of container ids.
//
// cJSON_ArrayForEach() walks an object's MEMBERS as readily as an array's
// elements, so a malformed answer would have produced ids taken from member
// names -- and the stale sweep deletes the rows of every container absent from
// what it is given. Nothing is swept on evidence this bad.
TEST_F(ContainerReportingTest, AMalformedContainerIdReplySweepsNothing)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    admission = {{"a", true}, {"b", true}};
    listed = false;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);

    // Both containers go away, so a working sweep would delete both. The query
    // that says which containers hold rows answers with an object instead.
    distinct_ids_malformed = true;
    admission.clear();
    files.clear();
    listed = false;
    fim_run_container_baseline();

    EXPECT_NE(syncFlag("a", "/etc/one"), -1) << "a malformed reply authorises no deletion";
    EXPECT_NE(syncFlag("b", "/etc/one"), -1);
}

// Once a container has spent its document budget, container_budget_decide()
// refuses every withheld row it is offered. Offering them anyway costs a query,
// a parse, a normalisation and a schema validation each, on every reconcile --
// and a reconcile runs on every admission change and every whole-node baseline,
// so a node sitting at its ceiling pays that for ever to learn nothing.
TEST_F(ContainerReportingTest, AFullBudgetIsNotOfferedItsWithheldRowsAgain)
{
    container_reporting_test_host(2);
    files = {{"a", {"/etc/one", "/etc/two", "/etc/three"}}};
    admission = {{"a", true}};
    listed = false;
    fim_run_container_baseline();

    // Two reported, one over the ceiling.
    int reported = 0;

    for (const char* path :
            {"/etc/one", "/etc/two", "/etc/three"
            })
    {
        reported += (syncFlag("a", path) == 1) ? 1 : 0;
    }

    ASSERT_EQ(reported, 2);

    // A reconcile with nothing changed. The budget is full, so the one withheld
    // row cannot be granted and must not be read.
    persist_attempts = 0;
    const char* known[] = {"a"};
    fim_container_set_admission(known, 1, known, 1);

    EXPECT_EQ(persist_attempts, 0u) << "a full budget refuses every withheld row; reading them learns nothing";

    // ...and the skip must not outlive the condition. Freeing the budget makes
    // the next reconcile offer the withheld row again.
    fim_container_doc_budget_release("a");
    container_reporting_test_host(10);
    persist_attempts = 0;
    fim_container_set_admission(known, 1, known, 1);

    EXPECT_GT(persist_attempts, 0u) << "with room again, the withheld row must get its chance";
    EXPECT_EQ(syncFlag("a", "/etc/three"), 1);
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

// The connector and both consumers share a process, so the agent
// restart that opens the connector's settling window starts the consumers from
// scratch too -- with nothing installed, and with the rows the cap refused last
// run still at sync=0 in the database.
//
// "Not told yet" fails open, deliberately, so an agent that has not reached the
// connector does not look like one whose every container was capped. That is
// right for a connector too old to decide and wrong for one that is merely
// settling, and before this they were the same state: the bridge reported
// everything for the whole window, re-created the refused rows on the manager,
// and deleted them again when the verdict landed. Every restart.
TEST_F(ContainerReportingTest, APendingVerdictHoldsRatherThanFailingOpenAtAColdStart)
{
    // Nothing installed, exactly as a fresh process finds it.
    EXPECT_NE(fim_container_is_admitted("a"), 0) << "nothing heard at all still fails open";

    fim_container_set_admission_pending(1);

    EXPECT_EQ(fim_container_is_admitted("a"), 0)
            << "a connector that says it is settling is not a connector that cannot decide";
    EXPECT_EQ(fim_container_is_admitted("never-seen"), 0) << "including a container nothing has mentioned";

    // The host is not a container and never waits on a container verdict.
    EXPECT_NE(fim_container_is_admitted(""), 0);

    // A real verdict ends the wait and is applied in full, without needing the
    // flag cleared separately.
    const char* known[] = {"a", "b"};
    const char* admitted[] = {"a"};
    fim_container_set_admission(known, 2, admitted, 1);

    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0) << "and now absence IS a refusal";
}

// The mirror, and the reason the hold must be bounded: an unreachable connector
// has withdrawn the claim that a verdict is coming. Holding the node's rows on
// the strength of it would be unbounded, so the state falls back to what this
// path did before the flag existed.
TEST_F(ContainerReportingTest, AnUnreachableConnectorDoesNotLeaveTheNodeHeldForEver)
{
    using fim_container_events::ContainerEventDrain;
    using fim_container_events::ContainerEventDrainTestPeer;
    char directory[] = "/tmp/fim-admission-XXXXXX";
    ASSERT_NE(::mkdtemp(directory), nullptr);
    fim_container_events::DrainConfig config;
    config.connector_socket_path = std::string(directory) + "/connector";
    ContainerEventDrainTestPeer::initialize(config);
    drain_socket_path = config.connector_socket_path;
    const std::string reply =
        R"({"status":"ok","containers":[{"container_id":"a","cgroup_id":"11","synced":true},{"container_id":"b","cgroup_id":"12","synced":false}],"admitted":["a"],"known_unkeyed":[]})";
    ContainerEventDrain::instance().release();
    drain_list_reply = reply + "\n";
    ContainerEventDrainTestPeer::refresh();
    ASSERT_EQ(fim_container_is_admitted("b"), 0);
    ASSERT_EQ(ContainerEventDrainTestPeer::mappedContainers(), (std::set<std::string> {"a", "b"}));

    // The baseline stores a row while held; an unavailable drain poll must
    // promote it once released, using the installed answer rather than an
    // empty replacement. No filesystem re-walk is involved.
    files["a"] = {"/etc/one"};
    pending_replies = 1;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 0);
    ASSERT_EQ(fim_container_admission_pending(), 1);
    persisted.clear();
    ContainerEventDrainTestPeer::refresh();

    EXPECT_EQ(fim_container_admission_pending(), 0);
    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0) << "the installed refusal survives";
    EXPECT_EQ(fim_container_admission_is_stale("b"), 0);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(ContainerEventDrainTestPeer::mappedContainers(), (std::set<std::string> {"a", "b"}));

    // Another writer replaced the bridge while the resolver was unreachable.
    // Its own view has not changed, but the reachable answer must still land.
    const char* known[] = {"a", "b"};
    fim_container_set_admission(known, 2, nullptr, 0);
    ASSERT_EQ(fim_container_is_admitted("a"), 0);
    drain_list_reply = reply + "\n";
    ContainerEventDrainTestPeer::refresh();
    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(baseline_walks, 1u);
    ContainerEventDrain::instance().stop();
    EXPECT_EQ(::rmdir(directory), 0);
}

TEST_F(ContainerReportingTest, AnUnavailablePollWaitsForReleaseBeforeReconcilingStoredRows)
{
    using fim_container_events::ContainerEventDrain;
    using fim_container_events::ContainerEventDrainTestPeer;
    fim_container_events::DrainConfig config;
    config.connector_socket_path = "/tmp/fim-admission-no-such-connector";
    ContainerEventDrainTestPeer::initialize(config);
    const char* known[] = {"a"};
    fim_container_set_admission(known, 1, known, 1);
    files["a"] = {"/etc/one"};
    pending_replies = 1;
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 0);
    const auto queries = distinct_id_queries;

    ContainerEventDrainTestPeer::refresh();

    EXPECT_EQ(fim_container_admission_pending(), 0);
    EXPECT_EQ(distinct_id_queries, queries) << "the walk has not released reconciliation";
    EXPECT_EQ(syncFlag("a", "/etc/one"), 0);
    ContainerEventDrain::instance().release();
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(baseline_walks, 1u);
}

TEST_F(ContainerReportingTest, TheAdmissionListingDoesNotHoldTheRecoveryTransactionLock)
{
    std::promise<void> entered;
    std::promise<void> reply;
    auto canReply = reply.get_future().share();
    on_listing_reply = [&]
    {
        entered.set_value();
        canReply.wait();
    };
    auto baseline = std::async(std::launch::async, [] { fim_run_container_baseline(); });
    entered.get_future().wait();
    const bool acquired = fim_container_state_trylock();
    EXPECT_TRUE(acquired) << "recovery must not wait behind the listing RPC";

    if (acquired) fim_container_state_unlock();

    reply.set_value();
    baseline.get();
}

TEST_F(ContainerReportingTest, AnEngineFailureStillWarnsThatChangesWillNotBeDetected)
{
    fim_container_events_start();
    fim_container_events_stop();
    EXPECT_EQ(std::count_if(warnings.begin(), warnings.end(), [](const auto & warning)
    {
        return warning.find("changes will NOT be detected after the initial baseline") != std::string::npos;
    }), 1);
}

TEST_F(ContainerReportingTest, AnEngineFailureReportsTheEnabledPeriodicWalk)
{
    container_reporting_test_frequency(1800);
    fim_container_events_start();
    fim_container_events_stop();
    EXPECT_EQ(std::count_if(warnings.begin(), warnings.end(), [](const auto & warning)
    {
        return warning.find("periodic container walk every 1800 seconds") != std::string::npos;
    }), 1);
    EXPECT_EQ(std::count_if(warnings.begin(), warnings.end(), [](const auto & warning)
    {
        return warning.find("will NOT be detected") != std::string::npos;
    }), 0);
}

TEST_F(ContainerReportingTest, AFailedDrainSettlesAdmissionWithoutAnotherFilesystemWalk)
{
    admission = {{"a", true}, {"b", false}};
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/two"}}};
    pending_replies = 1;
    std::atomic<bool> settled {false};
    auto config = resolverConfig();
    drain_reply_provider = [&] { return settled.load() ? settled_reply : pending_reply; };
    EXPECT_FALSE(fim_container_events::ContainerEventDrain::instance().start(config, {}));
    ASSERT_FALSE(fim_container_events::ContainerEventDrain::instance().running());
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 0);
    ASSERT_EQ(syncFlag("b", "/etc/two"), 0);
    ASSERT_TRUE(persisted.empty());

    fim_container_events_release();
    fim_container_events_release(); // Releasing twice must not start another worker.
    settled = true;
    ASSERT_TRUE(waitFor([] { return !fim_container_admission_pending(); }, std::chrono::seconds {2}));
    fim_container_events_stop(); // Join before reading rows or callback collections.

    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);
    EXPECT_EQ(persisted, (std::vector<std::pair<std::string, int>> {{"a:/etc/one", OPERATION_CREATE}}));
    EXPECT_EQ(baseline_walks, 1u);
}

TEST_F(ContainerReportingTest, AdmissionOnlyConsumesResolverCleanupAfterRelease)
{
    using fim_container_events::ContainerEventDrain;
    using fim_container_events::ReconcileMode;
    std::atomic<bool> consumed {false};
    auto config = resolverConfig();
    drain_reply_provider = [] { return settled_reply; };
    EXPECT_FALSE(ContainerEventDrain::instance().start(config, [&](const auto& request)
    {
        if (request.mode == ReconcileMode::sweepAbsent) consumed = true;
    }));
    EXPECT_FALSE(ContainerEventDrain::instance().running());

    // A changed whole-node list asks for cleanup without any kernel events.
    // Waiting for another request lets the first refresh finish, so this also
    // checks that queued cleanup stays behind the baseline's release gate.
    EXPECT_TRUE(waitFor([] { return resolver_list_requests.load() > 1; }, std::chrono::seconds {2}));
    EXPECT_FALSE(consumed.load());
    ContainerEventDrain::instance().release();
    EXPECT_TRUE(waitFor([&] { return consumed.load(); }, std::chrono::seconds {2}));
    ContainerEventDrain::instance().stopAdmission();
    ContainerEventDrain::instance().stopAdmission();
    ContainerEventDrain::instance().stop();
}

TEST_F(ContainerReportingTest, AdmissionOnlyUnavailabilityRetainsAnInstalledVerdict)
{
    const char* known[] = {"a", "b"};
    const char* admitted[] = {"a"};
    fim_container_set_admission(known, 2, admitted, 1);
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/two"}}};
    pending_replies = 1;
    fim_run_container_baseline();
    auto config = resolverConfig();
    drain_reply_provider = [] { return std::string {}; };
    EXPECT_FALSE(fim_container_events::ContainerEventDrain::instance().start(config, {}));
    fim_container_events_release();
    ASSERT_TRUE(waitFor([] { return !fim_container_admission_pending(); }, std::chrono::seconds {2}));

    // Waiting for the flag alone is not enough to observe the promotion it
    // leads to. The install clears container_admission_pending BEFORE calling
    // fim_container_reconcile_admission() -- it has to, because that function
    // refuses to act while a verdict is pending -- so a waiter on the flag can
    // be released in the window between the two and stop the drain before the
    // promotion runs. Wait for the state the verdict is supposed to produce.
    ASSERT_TRUE(waitFor([] { return syncFlag("a", "/etc/one") == 1; }, std::chrono::seconds {2}));
    fim_container_events_stop();

    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);
    EXPECT_EQ(fim_container_admission_is_stale("b"), 0);
    EXPECT_EQ(baseline_walks, 1u);
}

TEST_F(ContainerReportingTest, ShutdownInterruptsAdmissionWaitingForRecoveryAndPreventsALaterStart)
{
    auto config = resolverConfig();
    drain_reply_provider = [] { return pending_reply; };
    fim_container_set_admission_pending(1);
    fim_container_state_lock();
    EXPECT_FALSE(fim_container_events::ContainerEventDrain::instance().start(config, {}));
    // The request happens even while recovery owns the transaction lock. Its
    // application waits, and shutdown must be able to cancel that wait.
    EXPECT_TRUE(waitFor([] { return resolver_list_requests.load() > 0; }, std::chrono::seconds {2}));
    fim_container_events_stop_admission();
    fim_container_state_unlock();
    const auto requests = resolver_list_requests.load();
    fim_container_events_stop_admission(); // Idempotent even after the join.
    fim_container_events_start();
    fim_container_events_release();
    fim_container_events_stop();
    EXPECT_EQ(resolver_list_requests.load(), requests);
    EXPECT_EQ(fim_container_admission_pending(), 1);
}

TEST_F(ContainerReportingTest, AdmissionPollingContinuesBeyondTheOldDeadlineAndTheOutageBudgetIsBounded)
{
    using fim_container_events::ContainerEventDrainTestPeer;
    files["a"] = {"/etc/one"};
    pending_replies = 1;
    fim_run_container_baseline();
    auto config = resolverConfig();
    std::atomic<bool> available {true};
    drain_reply_provider = [&] { return available.load() ? pending_reply : std::string {}; };
    EXPECT_FALSE(fim_container_events::ContainerEventDrain::instance().start(config, {}));
    fim_container_events_release();
    ASSERT_TRUE(waitFor([] { return resolver_list_requests.load() > 0; }, std::chrono::seconds {2}));
    ContainerEventDrainTestPeer::advanceAdmissionTime(std::chrono::seconds {36});
    const auto before = resolver_list_requests.load();
    ASSERT_TRUE(waitFor([&] { return resolver_list_requests.load() > before + 1; }, std::chrono::seconds {2}));
    EXPECT_EQ(fim_container_admission_pending(), 1) << "reachable pending is not an outage";

    // Start a continuous outage, then advance only the policy clock. There is
    // no 35-second sleep and the resolver itself never expires.
    available = false;
    const auto beforeOutage = resolver_list_requests.load();
    ASSERT_TRUE(waitFor([&] { return resolver_list_requests.load() > beforeOutage + 1; }, std::chrono::seconds {2}));
    EXPECT_EQ(fim_container_admission_pending(), 1);
    ContainerEventDrainTestPeer::advanceAdmissionTime(fim_container_events::kConsumerOutageBudget
                                                      + std::chrono::milliseconds {1});
    ASSERT_TRUE(waitFor([] { return !fim_container_admission_pending(); }, std::chrono::seconds {2}));
    fim_container_events_stop_admission();
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(baseline_walks, 1u);
}

TEST_F(ContainerReportingTest, ReleaseDoesNotStartAdmissionWithoutStart)
{
    fim_container_set_admission_pending(1);
    fim_container_events_release();
    fim_container_events_stop();
    EXPECT_EQ(resolver_list_requests.load(), 0u);
    EXPECT_EQ(fim_container_admission_pending(), 1);
}

TEST_F(ContainerReportingTest, AColdStartTransientFailureKeepsTheHoldAndPromotesNothing)
{
    auto config = resolverConfig();
    fim_container_events::ContainerEventDrainTestPeer::initialize(config);
    admission = {{"a", true}, {"b", false}};
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/two"}}};
    pending_replies = 1;
    fim_run_container_baseline();
    fim_container_events_release();
    ASSERT_EQ(fim_container_admission_snapshot_known(), 0);
    const auto queries = distinct_id_queries;
    fim_container_events::ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 1);
    EXPECT_EQ(distinct_id_queries, queries);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 0);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);
    EXPECT_TRUE(persisted.empty());

    // The baseline's independent failed listing shares the same policy.
    connector_available = false;
    listed = false;
    fim_run_container_baseline();
    EXPECT_EQ(fim_container_admission_pending(), 1);
    EXPECT_TRUE(persisted.empty());
}

TEST_F(ContainerReportingTest, AColdStartSustainedOutageReleasesAndReconcilesExactlyOnce)
{
    using fim_container_events::ContainerEventDrainTestPeer;
    ContainerEventDrainTestPeer::initialize(resolverConfig());
    files["a"] = {"/etc/one"};
    pending_replies = 1;
    fim_run_container_baseline();
    fim_container_events_release();
    ContainerEventDrainTestPeer::refresh();
    ContainerEventDrainTestPeer::advanceAdmissionTime(fim_container_events::kConsumerOutageBudget);
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 1) << "the outage must exceed the budget";
    ContainerEventDrainTestPeer::advanceAdmissionTime(std::chrono::milliseconds {1});
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 0);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    const auto queries = distinct_id_queries;
    const auto sends = persisted.size();
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(distinct_id_queries, queries);
    EXPECT_EQ(persisted.size(), sends);
}

TEST_F(ContainerReportingTest, AColdStartVerdictAfterATransientFailureIsAppliedNormally)
{
    using fim_container_events::ContainerEventDrainTestPeer;
    ContainerEventDrainTestPeer::initialize(resolverConfig());
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/two"}}};
    pending_replies = 1;
    fim_run_container_baseline();
    fim_container_events_release();
    ContainerEventDrainTestPeer::refresh();
    ASSERT_EQ(fim_container_admission_snapshot_known(), 0);
    drain_list_reply = settled_reply;
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 0);
    EXPECT_EQ(fim_container_admission_snapshot_known(), 1);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);
}

TEST_F(ContainerReportingTest, AnySuccessfulListingResetsTheColdStartOutageClock)
{
    using fim_container_events::ContainerEventDrainTestPeer;
    ContainerEventDrainTestPeer::initialize(resolverConfig());
    fim_container_set_admission_pending(1);
    ContainerEventDrainTestPeer::refresh();
    ContainerEventDrainTestPeer::advanceAdmissionTime(fim_container_events::kConsumerOutageBudget);
    drain_list_reply = pending_reply;
    ContainerEventDrainTestPeer::refresh();
    ContainerEventDrainTestPeer::refresh(); // A fresh outage starts here.
    ContainerEventDrainTestPeer::advanceAdmissionTime(std::chrono::milliseconds {1});
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 1);

    // A successful listing from the other writer resets the same clock.
    pending_replies = 1;
    fim_run_container_baseline();
    ContainerEventDrainTestPeer::advanceAdmissionTime(fim_container_events::kConsumerOutageBudget);
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 1);
}

TEST_F(ContainerReportingTest, ShutdownWaitsForAnInflightAdmissionRequestBeforeTeardown)
{
    auto config = resolverConfig();
    std::promise<void> entered;
    std::promise<void> reply;
    auto canReply = reply.get_future().share();
    drain_reply_provider = [&]
    {
        entered.set_value();
        canReply.wait();
        return settled_reply;
    };
    EXPECT_FALSE(fim_container_events::ContainerEventDrain::instance().start(config, {}));
    entered.get_future().wait();
    auto stopped = std::async(std::launch::async, [] { fim_container_events_stop_admission(); });
    EXPECT_EQ(stopped.wait_for(std::chrono::milliseconds {20}), std::future_status::timeout);
    reply.set_value();
    ASSERT_EQ(stopped.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    stopped.get();
    const auto requests = resolver_list_requests.load();
    fim_db_teardown(); // Matches the waiter: only after the admission join.
    fim_container_events_start();
    fim_container_events_release();
    fim_container_events_stop();
    EXPECT_EQ(resolver_list_requests.load(), requests);
    EXPECT_EQ(distinct_id_queries, 0u) << "the shutdown reply was not published";
    fim_db_init(FIM_DB_MEMORY, [](modules_log_level_t, const char*) {}, 1000, 0, nullptr);
}

TEST_F(ContainerReportingTest, TheDrainWarnsOnceWhenSettlementStillLeavesASourceSilent)
{
    using fim_container_events::ContainerEventDrain;
    using fim_container_events::ContainerEventDrainTestPeer;
    fim_container_events::DrainConfig config;
    config.connector_socket_path = "/tmp/fim-admission-silent-source-test";
    drain_socket_path = config.connector_socket_path;
    ContainerEventDrainTestPeer::initialize(config);
    ContainerEventDrain::instance().release();
    fim_container_set_admission(nullptr, 0, nullptr, 0);
    warnings.clear();

    drain_list_reply = "{\"status\":\"ok\",\"containers\":[],\"admission_pending\":true,\"sources_pending\":true}\n";
    ContainerEventDrainTestPeer::refresh();
    EXPECT_TRUE(warnings.empty());

    const std::string settled = "{\"status\":\"ok\",\"containers\":[],\"sources_pending\":true}\n";
    drain_list_reply = settled;
    ContainerEventDrainTestPeer::refresh();
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("stale-container cleanup is not running"), std::string::npos);
    drain_list_reply = settled;
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(warnings.size(), 1u);

    // A baseline that sees the same still-silent source shares the warning;
    // it must not add a second one after the resolver already said it.
    sources_pending = true;
    fim_run_container_baseline();
    EXPECT_EQ(warnings.size(), 1u);
}

// The hold must end AT the install, not before it.
//
// Clearing it a few statements earlier left a window in which nothing was
// installed and the hold was already off, so a reader on another thread -- the
// event drain, or a row batch through the second refresh path -- fell through
// to fail-open and reported a container the caller was about to refuse. On a
// cold start nothing has ever been installed, so the fallback is wrong for the
// whole of that window.
TEST_F(ContainerReportingTest, TheHoldEndsAtomicallyWithTheVerdictItWaitedFor)
{
    fim_container_set_admission_pending(1);
    ASSERT_EQ(fim_container_is_admitted("refused"), 0);

    // The verdict arrives and refuses "refused". There must be no observable
    // state in which the hold is off and this container reads as admitted.
    const char* known[] = {"kept", "refused"};
    const char* admitted[] = {"kept"};
    fim_container_set_admission(known, 2, admitted, 1);

    EXPECT_EQ(fim_container_is_admitted("refused"), 0) << "held before, refused after; never admitted in between";
    EXPECT_NE(fim_container_is_admitted("kept"), 0);
}

// The request starts under one generation, a newer verdict arrives, and only
// then does the older pending reply return. The hook models that interleaving
// without relying on thread scheduling; the real bridge install advances the
// generation that the listing writer sampled before issuing its request.
TEST_F(ContainerReportingTest, AnOlderBaselinePendingReplyCannotRearmANewerVerdict)
{
    pending_replies = 1;
    on_listing_reply = []
    {
        const char* known[] = {"a", "b"};
        const char* admitted[] = {"a"};
        fim_container_set_admission(known, 2, admitted, 1);
    };
    const auto generation = fim_container_admission_generation();
    fim_run_container_baseline();

    EXPECT_GT(fim_container_admission_generation(), generation);
    EXPECT_EQ(fim_container_admission_pending(), 0);
    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0);

    // Knowing a verdict is not permission to ignore a later source's barrier.
    listed = false;
    pending_replies = 1;
    fim_run_container_baseline();
    EXPECT_EQ(fim_container_admission_pending(), 1);
    fim_container_set_admission_pending(0);
}

TEST_F(ContainerReportingTest, AnOlderDrainPendingReplyCannotRearmANewerVerdict)
{
    using fim_container_events::ContainerEventDrain;
    using fim_container_events::ContainerEventDrainTestPeer;
    fim_container_events::DrainConfig config;
    config.connector_socket_path = "/tmp/fim-admission-generation-test";
    drain_socket_path = config.connector_socket_path;
    ContainerEventDrainTestPeer::initialize(config);
    ContainerEventDrain::instance().release();
    const std::string pending = R"({"status":"ok","containers":[],"admission_pending":true})";
    drain_list_reply = pending + "\n";
    on_listing_reply = []
    {
        const char* known[] = {"a", "b"};
        const char* admitted[] = {"a"};
        fim_container_set_admission(known, 2, admitted, 1);
    };
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 0);
    EXPECT_NE(fim_container_is_admitted("a"), 0);
    EXPECT_EQ(fim_container_is_admitted("b"), 0);

    drain_list_reply = pending + "\n";
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 1) << "a fresh late-source barrier still holds";
    drain_list_reply = "{\"status\":\"ok\",\"containers\":[],\"known_unkeyed\":[]}\n";
    ContainerEventDrainTestPeer::refresh();
    EXPECT_EQ(fim_container_admission_pending(), 0) << "an unchanged empty view still publishes settlement";
}

TEST_F(ContainerReportingTest, ASupersededReconcileLeavesReportingFlagsAloneWhileAdmissionIsPending)
{
    admission = {{"a", true}, {"b", false}};
    files["a"] = {"/etc/one"};
    files["b"] = {"/etc/two"};
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/two"), 0);
    persisted.clear();
    const auto queries = distinct_id_queries;

    // A reconcile queued by an earlier verdict may acquire the state mutex
    // after the baseline has learned that the connector is settling again.
    // Pending is a reason to wait, never a decision to withdraw everything.
    fim_container_set_admission_pending(1);
    fim_container_reconcile_admission();

    EXPECT_TRUE(persisted.empty());
    EXPECT_EQ(distinct_id_queries, queries);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 0);

    const char* known[] = {"a", "b"};
    fim_container_set_admission(known, 2, known, 2);
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/two"), 1);
    EXPECT_EQ(persisted, (std::vector<std::pair<std::string, int>> {{"b:/etc/two", OPERATION_CREATE}}));
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

TEST_F(ContainerReportingTest, ScheduledSweepRemovesAnAbsentContainersRowsAndContext)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);
    ASSERT_TRUE(hasContext("b"));

    admission.erase("b");
    files.erase("b");
    listed = false;
    fim_container_sweep_absent();

    EXPECT_EQ(fim_db_count_container_rows("b", nullptr), 0);
    EXPECT_FALSE(hasContext("b"));
    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_TRUE(hasContext("a"));
}

TEST_F(ContainerReportingTest, ScheduledSweepKeepsAllRowsAndContextsWhenTheConnectorIsUnreachable)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);
    ASSERT_TRUE(hasContext("a"));
    ASSERT_TRUE(hasContext("b"));

    connector_available = false;
    admission.clear();
    files.clear();
    listed = false;
    persisted.clear();
    fim_container_sweep_absent();

    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/one"), 1);
    EXPECT_TRUE(hasContext("a"));
    EXPECT_TRUE(hasContext("b"));
    EXPECT_TRUE(persisted.empty());
}

TEST_F(ContainerReportingTest, ScheduledSweepKeepsListedContainersIncludingStoppedOnes)
{
    files = {{"a", {"/etc/one"}}, {"b", {"/etc/one"}}};
    fim_run_container_baseline();
    ASSERT_EQ(syncFlag("a", "/etc/one"), 1);
    ASSERT_EQ(syncFlag("b", "/etc/one"), 1);
    ASSERT_TRUE(hasContext("a"));
    ASSERT_TRUE(hasContext("b"));

    // A stopped container produces no walk rows but is still in the runtime's list.
    files.erase("b");
    listed = false;
    persisted.clear();
    fim_container_sweep_absent();

    EXPECT_EQ(syncFlag("a", "/etc/one"), 1);
    EXPECT_EQ(syncFlag("b", "/etc/one"), 1);
    EXPECT_TRUE(hasContext("a"));
    EXPECT_TRUE(hasContext("b"));
    EXPECT_TRUE(persisted.empty());
}

TEST_F(ContainerReportingTest, AReportedRemovalWaitsForAWalkHoldingTheLock)
{
    // The one writer of container rows that used to run unserialised. A removal
    // sweep racing a walk of the same container could delete that walk's rows,
    // see none remaining, release the budget and drop the context -- and then the
    // walk's own transaction re-inserted rows with no context to describe them.
    //
    // Proven by blocking inside the walk, which holds the transaction lock, and
    // showing the removal cannot finish until the walk lets go.
    files = {{"a", {"/etc/one"}}};

    std::mutex mutex;
    std::condition_variable cv;
    bool walkParked {false};
    bool releaseWalk {false};
    bool sweepEntered {false};
    bool sweepReturned {false};

    inside_walk = [&]
    {
        std::unique_lock<std::mutex> lock {mutex};
        walkParked = true;
        cv.notify_all();
        cv.wait(lock, [&] { return releaseWalk; });
    };

    std::thread walk {[] { fim_run_container_baseline(); }};

    {
        std::unique_lock<std::mutex> lock {mutex};
        ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(10), [&] { return walkParked; }))
                << "the walk never reached the hook";
    }

    std::thread removal {[&]
        {
            {
                std::lock_guard<std::mutex> lock {mutex};
                sweepEntered = true;
            }
            cv.notify_all();

            fim_container_events::ReconcileRequest request;
            request.mode = fim_container_events::ReconcileMode::containerGone;
            request.container_id = "a";
            fim_container_reconcile_batch_for_testing(request);

            {
                std::lock_guard<std::mutex> lock {mutex};
                sweepReturned = true;
            }
            cv.notify_all();
        }};

    {
        std::unique_lock<std::mutex> lock {mutex};
        ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(10), [&] { return sweepEntered; }))
                << "the removal thread never started";

        // It must still be blocked on the transaction lock. Without it the sweep
        // runs to completion here, inside the walk, which is the race itself.
        EXPECT_FALSE(cv.wait_for(lock, std::chrono::milliseconds(500), [&] { return sweepReturned; }))
                << "the removal swept while a walk held the transaction lock";

        releaseWalk = true;
    }

    cv.notify_all();
    walk.join();

    {
        std::unique_lock<std::mutex> lock {mutex};
        EXPECT_TRUE(cv.wait_for(lock, std::chrono::seconds(10), [&] { return sweepReturned; }))
                << "the removal never ran once the walk released the lock";
    }

    removal.join();
    inside_walk = {};

    // And it did sweep: the rows and the context are gone, not merely deferred.
    EXPECT_EQ(fim_db_count_container_rows("a", nullptr), 0);
    EXPECT_FALSE(hasContext("a"));
}

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

TEST_F(ContainerReportingTest, ConsumerBaselineHoldsTheDatabaseLifetimeBarrierAndReleasesOnException)
{
    files = {{"a", {"/etc/one"}}};
    bool injected = false;
    inside_walk = [&]
    {
        injected = true;
        // Probe from another thread: POSIX does not require a normal mutex to
        // diagnose a trylock by its owner.
        auto probe = std::async(std::launch::async, []
        {
            const int result = container_reporting_test_scan_trylock();
            if (result == 0) container_reporting_test_scan_unlock();
            return result;
        });
        EXPECT_EQ(probe.get(), EBUSY);
        throw std::runtime_error("injected walk failure");
    };
    fim_container_events::ReconcileRequest request;
    request.mode = fim_container_events::ReconcileMode::rebaselineAll;
    fim_container_reconcile_batch_for_testing(request);
    EXPECT_TRUE(injected);
    const int result = container_reporting_test_scan_trylock();
    EXPECT_EQ(result, 0);
    if (result == 0) container_reporting_test_scan_unlock();
}

TEST_F(ContainerReportingTest, EveryConsumerModeRechecksShutdownAfterTheDatabaseBarrier)
{
    using fim_container_events::ReconcileMode;
    files = {{"a", {"/etc/one"}}};
    fim_run_container_baseline();
    for (const auto mode : {ReconcileMode::rebaselineAll, ReconcileMode::rewalkContainer,
                           ReconcileMode::rereadPaths, ReconcileMode::deletePaths,
                           ReconcileMode::containerGone, ReconcileMode::sweepAbsent})
    {
        container_reporting_test_shutdown(false);
        ASSERT_EQ(container_reporting_test_scan_trylock(), 0);
        fim_container_events::ReconcileRequest request;
        request.mode = mode;
        request.container_id = "a";
        request.paths = {"/etc/one"};
        auto batch = std::async(std::launch::async, [&]
        {
            fim_container_reconcile_batch_for_testing(request);
        });
        EXPECT_EQ(batch.wait_for(std::chrono::milliseconds(50)), std::future_status::timeout);
        container_reporting_test_shutdown(true);
        container_reporting_test_scan_unlock();
        batch.get();
        EXPECT_EQ(fim_db_count_container_rows("a", nullptr), 1);
        const int result = container_reporting_test_scan_trylock();
        EXPECT_EQ(result, 0);
        if (result == 0) container_reporting_test_scan_unlock();
    }
    container_reporting_test_shutdown(false);
}
