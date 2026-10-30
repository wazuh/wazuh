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

    /* Which of those the cap refused. The connector ranks them like any other
     * container, so the shim reports each one's decision through the id sink;
     * empty means it admitted them all, which is the ordinary case. */
    std::set<std::string> unkeyed_refused;
    bool reject_persistence = false;
    std::size_t persist_attempts = 0;
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
                unkeyed_refused.clear();
                reject_persistence = false;
                persist_attempts = 0;
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

    if (unkeyed_known)
    {
        /* Exactly what the real shim does: the unkeyed ids go through the
         * unkeyed sink for the sweep AND through the id sink with the cap's
         * decision, because the cap ranks them too. */
        for (const auto& id : unkeyed)
        {
            if (unkeyed_sink) unkeyed_sink(id.c_str(), unkeyed_ctx);

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
 * reads its list behind a pimpl with a live socket, so the partial-listing
 * rule shipped written down in a comment and never reached by the code.
 * These drive the whole decision for one reply.
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

// Keyed-complete and enumerated are different claims about one reply, and the
// drain used to have a single flag for both. Admission needs the second: it
// decides who may report, which is a question about ids.
TEST(ContainerListRefresh, AnIncompleteReplyThatNamesWhatItCouldNotKeyStillDecidesAdmission)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using fim_container_events::AdmissionPublish;
    using fim_container_events::decideAdmissionPublish;
    using fim_container_events::planListRefresh;

    ContainerRef keyed;
    keyed.containerId = "a";
    keyed.cgroupId = 11;
    keyed.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = false; // a full list
    delta.complete = false;       // ...that "stuck" is missing from
    delta.containers = {keyed};
    delta.unkeyedKnown = true;
    delta.unkeyed = {"stuck"};
    delta.admittedKnown = true;
    delta.admitted = {"a"}; // ...and the cap ranked "stuck" and turned it down

    const auto plan = planListRefresh(delta, {});

    ASSERT_TRUE(plan.act);
    EXPECT_FALSE(plan.complete) << "there is no cgroup id to put in the map for 'stuck'";
    EXPECT_TRUE(plan.enumerated) << "but the reply does name every container that exists";
    EXPECT_FALSE(plan.installWholeList);

    EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"a", true}, {"stuck", false}}))
            << "an unkeyed container is ranked like any other, so its refusal is an answer";

    for (const auto& [cgroup, id] : plan.containers)
    {
        EXPECT_NE(id, "stuck") << "an id with no host key must never reach the cgroup map";
    }

    for (const auto& event : plan.events)
    {
        EXPECT_NE(event.container_id, "stuck") << "nor the kernel filter, by any other route";
    }

    // And that is enough to install. Waiting for 'stuck' to be keyed means
    // waiting for as long as it runs.
    EXPECT_EQ(decideAdmissionPublish(true, false, true, plan.enumerated), AdmissionPublish::install);
    EXPECT_EQ(decideAdmissionPublish(true, false, true, false), AdmissionPublish::defer)
            << "a connector too old to say what it could not key leaves nothing to go on";
}

// Lowering containers.synced_limit must reach this path, and one container
// nobody can key used to stop it.
//
// The whole admitted set is the only place a withdrawal with no event of its
// own can arrive, and absence from it was read as a refusal only on a reply
// where every container was KEYED. A node with one unkeyable container never
// produces such a reply, so the drain went on republishing as admitted the
// containers the baseline had already retracted, and their documents alternated
// between CREATE and DELETE every cycle (#37532).
TEST(ContainerListRefresh, AWithdrawalArrivesEvenWhileOneContainerCannotBeKeyed)
{
    using wazuh::container_instances_client::ContainerDelta;
    using fim_container_events::planListRefresh;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = true;
    delta.complete = false; // 'stuck' has no key and never will
    delta.unkeyedKnown = true;
    delta.unkeyed = {"stuck"};
    delta.admittedKnown = true;
    delta.admitted = {"a"}; // the operator lowered the limit; 'b' lost its slot

    // No event names 'b': admission moves without one, which is why the set is
    // sent at all.
    const auto plan = planListRefresh(delta, {{"a", true}, {"b", true}});

    ASSERT_TRUE(plan.act);
    EXPECT_FALSE(plan.complete);
    EXPECT_TRUE(plan.enumerated) << "the reply still names every container that exists";
    EXPECT_FALSE(plan.admissionView.at("b")) << "the withdrawal must not wait for 'stuck' to be keyed";
    EXPECT_TRUE(plan.admissionView.at("a"));
}

// The one case where a consumer still has to supply the answer, because the
// connector gave none. A build too old to send the admitted set says nothing
// about the containers it could not key, and reading silence as a refusal
// retracts every row a live container holds -- so they are admitted, which is
// where the three-state reading came from in the first place.
TEST(ContainerListRefresh, WithoutAnAdmittedSetAnUnkeyedContainerIsStillAdmitted)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using fim_container_events::planListRefresh;

    ContainerRef keyed;
    keyed.containerId = "a";
    keyed.cgroupId = 11;
    keyed.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = false;
    delta.complete = false;
    delta.containers = {keyed};
    delta.unkeyedKnown = true;
    delta.unkeyed = {"stuck"};
    delta.admittedKnown = false; // an older container_instances

    const auto plan = planListRefresh(delta, {});

    ASSERT_TRUE(plan.act);
    EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"a", true}, {"stuck", true}}))
            << "no decision arrived, and silence is not a refusal";
}

// A resync that cannot be installed wholesale still has to say what has GONE.
//
// Upserts never remove anything, so a container that went away while the
// cursor was invalid kept its cgroups in the map, and allowed in the kernel,
// for as long as one container on the node could not be keyed. The kernel is
// then free to hand that inode to something else, and whatever lands on it is
// filed under a container that no longer exists (#37532).
TEST(ContainerListRefresh, AnIncompleteResyncStillWithdrawsContainersThatHaveGone)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using fim_container_events::CgroupDeltaEvent;
    using fim_container_events::planListRefresh;

    ContainerRef alive;
    alive.containerId = "alive";
    alive.cgroupId = 11;
    alive.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = true;
    delta.resyncRequired = true; // the cursor is from another store lifetime
    delta.complete = false;      // ...and "stuck" cannot be keyed
    delta.containers = {alive};
    delta.unkeyedKnown = true;
    delta.unkeyed = {"stuck"};

    // The map still holds all three from before the cursor went bad.
    const auto plan = planListRefresh(delta, {}, {"alive", "stuck", "gone"});

    ASSERT_TRUE(plan.act);
    ASSERT_FALSE(plan.installWholeList) << "there is no cgroup id for 'stuck' to install";

    std::map<std::string, CgroupDeltaEvent::Kind> kinds;

    for (const auto& event : plan.events)
    {
        kinds[event.container_id] = event.kind;
    }

    ASSERT_EQ(kinds.count("gone"), 1U) << "nothing else will ever withdraw it";
    EXPECT_EQ(kinds["gone"], CgroupDeltaEvent::Kind::removed);

    EXPECT_EQ(kinds.count("stuck"), 0U)
            << "a container the resolver cannot key has not gone anywhere; withdrawing it "
               "turns its next event into an escalation";
    ASSERT_EQ(kinds.count("alive"), 1U);
    EXPECT_EQ(kinds["alive"], CgroupDeltaEvent::Kind::changed);
}

// ...but only when the reply can say what it left out. Otherwise absence is
// not evidence of anything, and this is the false delete R1 was about.
TEST(ContainerListRefresh, AnUnenumeratedResyncWithdrawsNothing)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using fim_container_events::planListRefresh;

    ContainerRef alive;
    alive.containerId = "alive";
    alive.cgroupId = 11;
    alive.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = false; // an older connector
    delta.complete = false;
    delta.containers = {alive};
    delta.unkeyedKnown = false; // ...which cannot say what it could not key

    const auto plan = planListRefresh(delta, {}, {"alive", "gone"});

    ASSERT_TRUE(plan.act);
    EXPECT_FALSE(plan.enumerated);

    for (const auto& event : plan.events)
    {
        EXPECT_NE(event.container_id, "gone")
                << "'gone' may simply be one the connector could not key and did not mention";
    }
}

// A complete reply needs none of this: install() removes what the list omits,
// which is the whole reason it may only be used when every key is known.
TEST(ContainerListRefresh, ACompleteResyncLeavesTheRemovalsToInstall)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using fim_container_events::planListRefresh;

    ContainerRef alive;
    alive.containerId = "alive";
    alive.cgroupId = 11;
    alive.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = false;
    delta.complete = true;
    delta.containers = {alive};
    delta.unkeyedKnown = true;

    const auto plan = planListRefresh(delta, {}, {"alive", "gone"});

    ASSERT_TRUE(plan.act);
    EXPECT_TRUE(plan.installWholeList);
    EXPECT_TRUE(plan.events.empty()) << "install() replaces the map; naming departures too is noise";
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

// The cap bounds how many containers report, which is a question about ids and
// never about an attribution key. So a container the connector cannot key is
// ranked like any other, and its answer arrives the same way: in the admitted
// set, or absent from it.
//
// Treating it instead as unrankable -- admitting it because nothing had refused
// it -- is what let the node report past containers.synced_limit, and since a
// container is unkeyed for a while after every restart, that happened on every
// restart (#37532).
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
// with no attribution key too (#37532).
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
// from it and read as refused for the life of the process (#37532).
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
// that happen has nothing else to connect it to (#37532).
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

// Once a container has spent its document budget, container_budget_decide()
// refuses every withheld row it is offered. Offering them anyway costs a query,
// a parse, a normalisation and a schema validation each, on every reconcile --
// and a reconcile runs on every admission change and every whole-node baseline,
// so a node sitting at its ceiling pays that for ever to learn nothing (#37532).
TEST_F(ContainerReportingTest, AFullBudgetIsNotOfferedItsWithheldRowsAgain)
{
    container_reporting_test_host(2);
    files = {{"a", {"/etc/one", "/etc/two", "/etc/three"}}};
    admission = {{"a", true}};
    listed = false;
    fim_run_container_baseline();

    // Two reported, one over the ceiling.
    int reported = 0;

    for (const char* path : {"/etc/one", "/etc/two", "/etc/three"})
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
