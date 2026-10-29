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

#include "container_list_refresh.hpp"

namespace
{
    std::map<std::string, bool> admission;
    std::map<std::string, std::vector<std::string>> files;
    std::vector<std::pair<std::string, int>> persisted;
    std::vector<std::string> warnings;
    bool listed = false;
    bool connector_available = true;

    /* Whether the hooked listing claims to be the whole node. True is the
     * ordinary case; false models container_instances still resolving. */
    bool list_complete = true;

    /* Containers the hooked connector knows of but cannot key. */
    std::set<std::string> unkeyed;
    bool unkeyed_known = true;
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
                list_complete = true;
                unkeyed.clear();
                unkeyed_known = true;
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

    /* == 1, not truthiness: validate_and_persist_fim_event() sends only on
     * exactly 1, and the flag has negative values that mean "do not write the
     * column" rather than "report this". */
    if (sync_flag == 1)
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

extern "C" int __wrap_cbaseline_list_containers_ex(const char*,
                                                   cb_container_id_sink_t sink,
                                                   void* ctx,
                                                   cb_unkeyed_id_sink_t unkeyed_sink,
                                                   void* unkeyed_ctx,
                                                   cb_list_status_t* out_status)
{
    EXPECT_FALSE(listed) << "reuse the warm-up-guarded listing";
    listed = true;

    /* A listing that failed says nothing about its own coverage, matching the
     * real shim. */
    if (out_status)
    {
        out_status->complete = 0;
        out_status->unkeyed_known = 0;
    }

    if (!connector_available)
        return -1;

    for (const auto& [id, admitted] : admission) sink(id.c_str(), admitted, ctx);

    if (unkeyed_known && unkeyed_sink)
    {
        for (const auto& id : unkeyed) unkeyed_sink(id.c_str(), unkeyed_ctx);
    }

    if (out_status)
    {
        /* A connector that reports WHICH containers it could not key cannot then
         * disagree with itself about whether any exist -- the real one derives
         * `withheld` from that very set. Derived here too, so no test can model
         * a server that cannot exist. */
        const bool complete = unkeyed_known ? unkeyed.empty() : list_complete;
        out_status->complete = complete ? 1 : 0;
        out_status->unkeyed_known = unkeyed_known ? 1 : 0;
    }

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

/* The three rules above are only worth anything if the refresh actually
 * applies them, and for a long time nothing checked that it did: the drain
 * reads its list behind a pimpl with a live socket, so R1 shipped with the
 * partial-listing rule written down and never reached. These drive the whole
 * decision for one reply.
 */
TEST(ContainerListRefresh, AnUnansweredQueryChangesNothingAtAll)
{
    using wazuh::container_instances_client::ContainerDelta;
    using fim_container_events::planListRefresh;

    ContainerDelta delta; // available defaults to false
    const auto plan = planListRefresh(delta, {{"a", true}});

    EXPECT_FALSE(plan.act) << "an unanswered query is not an empty node";
    EXPECT_TRUE(plan.containers.empty());
    EXPECT_TRUE(plan.events.empty());
}

TEST(ContainerListRefresh, AFullListInstallsOnlyWhenItCoversEverything)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using fim_container_events::planListRefresh;

    ContainerRef a;
    a.containerId = "a";
    a.cgroupId    = 11;
    a.synced      = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = false; // an older server: the whole set, no cursor
    delta.containers = {a};
    delta.complete = true;

    {
        const auto plan = planListRefresh(delta, {{"a", true}, {"b", true}});
        EXPECT_TRUE(plan.act);
        EXPECT_TRUE(plan.installWholeList) << "a complete list may replace the map";
        EXPECT_EQ(plan.containers, (std::vector<std::pair<std::uint64_t, std::string>> {{11, "a"}}));
        EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"a", true}}))
                << "b is absent from a complete list, so b is gone";
    }

    // The same reply, still resolving. Nothing may be removed on the strength
    // of it -- not from the cgroup map, and not from admission.
    delta.complete = false;
    {
        const auto plan = planListRefresh(delta, {{"a", true}, {"b", true}});
        EXPECT_FALSE(plan.installWholeList) << "a partial list must upsert, never install";
        ASSERT_EQ(plan.events.size(), 1U);
        EXPECT_EQ(plan.events[0].container_id, "a");
        EXPECT_EQ(plan.events[0].kind, fim_container_events::CgroupDeltaEvent::Kind::changed);
        EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"a", true}, {"b", true}}))
                << "b was merely not spoken about";
        EXPECT_FALSE(plan.complete);
    }
}

TEST(ContainerListRefresh, ADeltaMergesItsEventsAndThenTheAdmittedSet)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerEventRef;
    using fim_container_events::planListRefresh;

    ContainerEventRef gone;
    gone.containerId = "gone";
    gone.kind = ContainerEventRef::Kind::removed;

    ContainerEventRef fresh;
    fresh.containerId = "fresh";
    fresh.cgroupId = 22;
    fresh.kind = ContainerEventRef::Kind::added;
    fresh.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = true;
    delta.complete = true;
    delta.events = {gone, fresh};

    // "quiet" has no event of its own, and the connector has just readmitted it
    // with the slot "gone" freed. Only the admitted set can say so.
    delta.admittedKnown = true;
    delta.admitted = {"fresh", "quiet"};

    const auto plan = planListRefresh(delta, {{"gone", true}, {"quiet", false}});

    EXPECT_TRUE(plan.act);
    EXPECT_FALSE(plan.installWholeList) << "a delta describes transitions, it never replaces the map";
    ASSERT_EQ(plan.events.size(), 2U);
    EXPECT_EQ(plan.events[0].kind, fim_container_events::CgroupDeltaEvent::Kind::removed);
    EXPECT_EQ(plan.events[1].kind, fim_container_events::CgroupDeltaEvent::Kind::added);

    EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"fresh", true}, {"quiet", true}}))
            << "the removal drops out, and the readmission arrives with no event of its own";
}

TEST(ContainerDrainAdmissionView, AnIncompleteListUpsertsAndACompleteOneReplaces)
{
    using wazuh::container_instances_client::ContainerRef;
    using fim_container_events::mergeAdmissionView;

    const std::map<std::string, bool> current = {{"a", true}, {"b", true}};

    ContainerRef onlyA;
    onlyA.containerId = "a";
    onlyA.synced      = true;

    // The connector is still resolving, so b is missing for want of a key, not
    // because it stopped existing. Dropping it here installs an admission set
    // without b, and the bridge reads anything absent as "not admitted" -- which
    // retracts every one of b's reported rows while b is alive.
    EXPECT_EQ(mergeAdmissionView(current, {onlyA}, false), (std::map<std::string, bool> {{"a", true}, {"b", true}}))
            << "an incomplete list may not drop a container it never spoke about";

    // The same list, now claiming to be the whole node: b really is gone.
    EXPECT_EQ(mergeAdmissionView(current, {onlyA}, true), (std::map<std::string, bool> {{"a", true}}))
            << "a complete list is the whole truth, so absence is removal";

    // An incomplete list still applies what it DOES say, in both directions.
    ContainerRef bWithheld;
    bWithheld.containerId = "b";
    bWithheld.synced      = false;
    EXPECT_EQ(mergeAdmissionView(current, {bWithheld}, false),
    (std::map<std::string, bool> {{"a", true}, {"b", false}}))
            << "a container the partial list names is updated from it";
}

TEST(ContainerDrainAdmissionView, TheAdmittedSetReachesContainersWithNoEventOfTheirOwn)
{
    using fim_container_events::applyAdmittedSet;

    // b was pushed out by the cap earlier; a is reporting.
    const std::map<std::string, bool> start = {{"a", true}, {"b", false}};

    // a stops, freeing a slot, and the connector readmits b. b has no lifecycle
    // event of its own -- recomputeAdmittedLocked() journals nothing -- so a
    // view merged from events alone would keep it withheld for ever.
    {
        auto view = start;
        applyAdmittedSet(view, {"a", "b"}, true, true);
        EXPECT_EQ(view, (std::map<std::string, bool> {{"a", true}, {"b", true}}))
                << "a readmitted container must not need an event of its own to be readmitted";
    }

    // The other direction: the cap tightened and a is out. A complete reply is
    // authoritative about absence, so the cap actually starts biting.
    {
        auto view = start;
        applyAdmittedSet(view, {"b"}, true, true);
        EXPECT_EQ(view, (std::map<std::string, bool> {{"a", false}, {"b", true}}));
    }

    // On a PARTIAL reply, absence is not a withdrawal: an unresolved container
    // is missing from the set for want of a key, and reading that as "not
    // admitted" is the same false retraction the sweeps are held back to avoid.
    {
        auto view = start;
        applyAdmittedSet(view, {"b"}, true, false);
        EXPECT_EQ(view, (std::map<std::string, bool> {{"a", true}, {"b", true}}))
                << "a partial reply may add admission but never take it away";
    }

    // A server too old to send the set leaves the view exactly as it was.
    {
        auto view = start;
        applyAdmittedSet(view, {}, false, true);
        EXPECT_EQ(view, start);
    }
}

TEST(ContainerDrainAdmissionView, ADeferredAdmissionSnapshotIsNotLostOnAQuietNode)
{
    using fim_container_events::AdmissionPublish;
    using fim_container_events::decideAdmissionPublish;

    // Nothing to say.
    EXPECT_EQ(decideAdmissionPublish(false, false, true, true), AdmissionPublish::nothing);

    // The ordinary case.
    EXPECT_EQ(decideAdmissionPublish(true, false, true, true), AdmissionPublish::install);

    // Held back before the baseline walk released, and held back while the
    // reply still omits containers the resolver cannot key -- installing that
    // marks them refused rather than unheard-of, which retracts live rows.
    EXPECT_EQ(decideAdmissionPublish(true, false, false, true), AdmissionPublish::defer);
    EXPECT_EQ(decideAdmissionPublish(true, false, true, false), AdmissionPublish::defer);

    // THE case. The caller already recorded the view it could not install, so
    // the next poll sees no change -- and on a quiet node no further change is
    // coming. Waiting for one means the cap is never applied at all.
    EXPECT_EQ(decideAdmissionPublish(false, true, true, true), AdmissionPublish::install)
            << "a snapshot deferred once must still be installed when nothing changes again";

    // ...but being owed one is not a reason to install it early.
    EXPECT_EQ(decideAdmissionPublish(false, true, false, true), AdmissionPublish::defer);
    EXPECT_EQ(decideAdmissionPublish(false, true, true, false), AdmissionPublish::defer);
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
    EXPECT_EQ(fim_persist_baseline_row("b:/etc/one", OPERATION_MODIFY, "wazuh-states-fim-files", reported, 2),
              FIM_CONTAINER_SYNC_UNCHANGED)
            << "the stored column must be left for the retraction to find";
    EXPECT_TRUE(persisted.empty()) << "a withheld container still reports nothing";

    // A row the manager never had is plainly withheld, exactly as before.
    const char* unreported = R"({"container_id":"b","path":"/etc/two","version":1,"size":1,"sync":0})";
    EXPECT_EQ(fim_persist_baseline_row("b:/etc/two", OPERATION_MODIFY, "wazuh-states-fim-files", unreported, 2), 0)
            << "nothing is owed for a row the manager never saw";
    EXPECT_TRUE(persisted.empty());
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
