/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The list-refresh planner decides what one container_instances list reply
 * does to a consumer's cgroup map and admission view. Its consumers read the
 * list behind a live socket, so these drive the whole decision for one reply
 * without one.
 */

#include "container_list_refresh.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

TEST(ContainerListRefresh, AnUnansweredQueryChangesNothingAtAll)
{
    using wazuh::container_instances_client::ContainerDelta;
    using container_attribution::planListRefresh;

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
    using container_attribution::planListRefresh;

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
        EXPECT_EQ(plan.events[0].kind, container_attribution::CgroupDeltaEvent::Kind::changed);
        EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"a", true}, {"b", true}}))
                << "b was merely not spoken about";
        EXPECT_FALSE(plan.complete);
    }
}

TEST(ContainerListRefresh, ADeltaMergesItsEventsAndThenTheAdmittedSet)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerEventRef;
    using container_attribution::planListRefresh;

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
    EXPECT_EQ(plan.events[0].kind, container_attribution::CgroupDeltaEvent::Kind::removed);
    EXPECT_EQ(plan.events[1].kind, container_attribution::CgroupDeltaEvent::Kind::added);

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
    using container_attribution::AdmissionPublish;
    using container_attribution::decideAdmissionPublish;
    using container_attribution::planListRefresh;

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
// between CREATE and DELETE every cycle.
TEST(ContainerListRefresh, AWithdrawalArrivesEvenWhileOneContainerCannotBeKeyed)
{
    using wazuh::container_instances_client::ContainerDelta;
    using container_attribution::planListRefresh;

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
    using container_attribution::planListRefresh;

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

// ...and it has to say so to the admission view as well as to the kernel.
//
// An incomplete resync MERGES, so on this path nothing ever removed from the
// view. A container that went away while the cursor was invalid stayed in it
// for the life of the process: the view grew without bound on a host that
// churns containers, the departed container went on holding a place in the set
// the drain publishes, and its id read as known rather than unheard-of if the
// runtime handed it out again. The delta path has erased on `removed` all
// along, for the same reasons.
TEST(ContainerListRefresh, AnIncompleteResyncDropsDepartedContainersFromTheAdmissionView)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using container_attribution::planListRefresh;

    ContainerRef stillHere;
    stillHere.containerId = "a";
    stillHere.cgroupId = 11;
    stillHere.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = false; // a full list...
    delta.complete = false;       // ...that cannot be installed wholesale
    delta.containers = {stillHere};
    delta.unkeyedKnown = true;
    delta.unkeyed = {"stuck"};
    delta.admittedKnown = true;
    delta.admitted = {"a", "stuck"};

    // "gone" was admitted when the cursor was last valid and is in no part of
    // this reply.
    const auto plan = planListRefresh(delta, {{"a", true}, {"gone", true}});

    ASSERT_TRUE(plan.act);
    ASSERT_TRUE(plan.enumerated);
    EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"a", true}, {"stuck", true}}));
    EXPECT_EQ(plan.admissionView.count("gone"), 0U) << "the reply names every container that exists, and not this one";
}

// A container that is deleted while it never had a key leaves the drain's view
// only if the drain notices it has stopped being unkeyed.
//
// It got in from the LIST side, through the connector's unkeyed set, and no
// event will ever take it out: the store erases a record that never had a key
// without journalling it, because a container that was never published has no
// visibility transition to report. So the id sat in the admission view for the
// life of the process -- unbounded growth on a node that churns containers the
// resolver cannot key, plus a departed container still answering
// fim_container_is_admitted() and still reading as known if its id comes round
// again.
TEST(ContainerListRefresh, AnUnkeyedContainerThatDisappearsLeavesTheAdmissionView)
{
    using wazuh::container_instances_client::ContainerDelta;
    using container_attribution::planListRefresh;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = true;
    delta.complete = false;
    delta.unkeyedKnown = true;
    delta.unkeyed = {"stuck"}; // "gone" was unkeyed last time and is not named now
    delta.admittedKnown = true;
    delta.admitted = {"a", "stuck"};

    const auto plan = planListRefresh(
    delta, {{"a", true}, {"gone", true}, {"stuck", true}}, {}, /*previousUnkeyed=*/ {"gone", "stuck"});

    ASSERT_TRUE(plan.act);
    EXPECT_EQ(plan.admissionView, (std::map<std::string, bool> {{"a", true}, {"stuck", true}}));
    EXPECT_EQ(plan.admissionView.count("gone"), 0U) << "no event retracts it, so the unkeyed set has to";

    // ...and the caller is handed what to compare against next time.
    EXPECT_EQ(plan.unkeyed, (std::set<std::string> {"stuck"}));
}

// The same id leaving the unkeyed set because it was KEYED is not a departure,
// and the reply that says so names it. Retiring happens before the events are
// applied so the event puts it straight back, this time with a cgroup id.
TEST(ContainerListRefresh, AnUnkeyedContainerThatGetsAKeyStaysInTheView)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerEventRef;
    using container_attribution::planListRefresh;

    ContainerEventRef keyed;
    keyed.containerId = "late";
    keyed.cgroupId = 77;
    keyed.kind = ContainerEventRef::Kind::changed;
    keyed.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = true;
    delta.complete = true;
    delta.unkeyedKnown = true;
    delta.unkeyed = {}; // "late" has a key now
    delta.admittedKnown = true;
    delta.admitted = {"late"};
    delta.events = {keyed};

    const auto plan = planListRefresh(delta, {{"late", true}}, {}, /*previousUnkeyed=*/ {"late"});

    ASSERT_TRUE(plan.act);
    EXPECT_EQ(plan.admissionView.count("late"), 1U) << "keyed, not gone -- and the reply says which";
    EXPECT_TRUE(plan.admissionView.at("late"));
    EXPECT_TRUE(plan.unkeyed.empty());
}

// A reply that cannot say what it could not key cannot say one has gone either.
// Carrying the previous set forward is what stops the next enumerating reply
// reading a container it never heard about as a departure.
TEST(ContainerListRefresh, AReplyThatCannotEnumerateRetiresNothingAndKeepsTheUnkeyedSet)
{
    using wazuh::container_instances_client::ContainerDelta;
    using container_attribution::planListRefresh;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = true;
    delta.complete = false;
    delta.unkeyedKnown = false; // an older container_instances

    const auto plan = planListRefresh(delta, {{"stuck", true}}, {}, /*previousUnkeyed=*/ {"stuck"});

    ASSERT_TRUE(plan.act);
    ASSERT_FALSE(plan.enumerated);
    EXPECT_EQ(plan.admissionView.count("stuck"), 1U) << "absence says nothing here";
    EXPECT_EQ(plan.unkeyed, (std::set<std::string> {"stuck"})) << "and the set is carried, not cleared";
}

// ...but only when the reply can tell "gone" from "not mentioned". A connector
// too old to name what it could not key leaves absence meaning nothing, and
// dropping a container on that evidence retracts the rows of one that is
// merely unresolved.
TEST(ContainerListRefresh, AResyncThatCannotEnumerateKeepsEveryContainerItDoesNotMention)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using container_attribution::planListRefresh;

    ContainerRef stillHere;
    stillHere.containerId = "a";
    stillHere.cgroupId = 11;
    stillHere.synced = true;

    ContainerDelta delta;
    delta.available = true;
    delta.deltaSupported = false;
    delta.complete = false;
    delta.containers = {stillHere};
    delta.unkeyedKnown = false; // an older container_instances

    const auto plan = planListRefresh(delta, {{"a", true}, {"maybe", true}});

    ASSERT_TRUE(plan.act);
    ASSERT_FALSE(plan.enumerated);
    EXPECT_EQ(plan.admissionView.count("maybe"), 1U) << "absence says nothing here, so it is not a departure";
}

// A resync that cannot be installed wholesale still has to say what has GONE.
//
// Upserts never remove anything, so a container that went away while the
// cursor was invalid kept its cgroups in the map, and allowed in the kernel,
// for as long as one container on the node could not be keyed. The kernel is
// then free to hand that inode to something else, and whatever lands on it is
// filed under a container that no longer exists.
TEST(ContainerListRefresh, AnIncompleteResyncStillWithdrawsContainersThatHaveGone)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using container_attribution::CgroupDeltaEvent;
    using container_attribution::planListRefresh;

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
    using container_attribution::planListRefresh;

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
    using container_attribution::planListRefresh;

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
    using container_attribution::mergeAdmissionView;

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

// The window after an agent restart, during which the connector has a
// verdict coming but has not reached it.
//
// The reply then carries no per-record `synced` at all -- and ContainerRef and
// ContainerEventRef both default it to TRUE, deliberately, so a connector too
// old to decide keeps everything reporting. Taking that default here wrote
// "admitted" over refusals the connector was about to re-issue: on a modulesd
// restart the drain re-admitted the containers the cap had pushed out, their
// documents were created on the manager, and settlement deleted them again a
// few seconds later.
TEST(ContainerDrainAdmissionView, APendingVerdictFreezesWhatIsKnownAndHoldsBackWhatIsNot)
{
    using wazuh::container_instances_client::ContainerRef;
    using container_attribution::mergeAdmissionView;

    // b was refused by the cap before the restart; c is brand new.
    const std::map<std::string, bool> current = {{"a", true}, {"b", false}};

    ContainerRef a;
    a.containerId = "a";
    // Not set by the parser, because the reply omits the key while pending.
    // This is the default that used to leak through.
    a.synced = true;

    ContainerRef b;
    b.containerId = "b";
    b.synced      = true;

    ContainerRef c;
    c.containerId = "c";
    c.synced      = true;

    const auto frozen = mergeAdmissionView(current, {a, b, c}, /*complete=*/false, /*admissionPending=*/true);

    EXPECT_EQ(frozen,
    (std::map<std::string, bool> {{"a", true}, {"b", false}, {"c", false}}))
            << "b keeps its refusal, and c waits rather than reporting on a default nobody decided";

    // And once the verdict lands the same reply is applied in full, including
    // the promotion of c. Freezing is for the window, not a new policy.
    const auto settled = mergeAdmissionView(frozen, {a, b, c}, /*complete=*/true, /*admissionPending=*/false);
    EXPECT_EQ(settled, (std::map<std::string, bool> {{"a", true}, {"b", true}, {"c", true}}));
}

TEST(ContainerDrainAdmissionView, TheAdmittedSetReachesContainersWithNoEventOfTheirOwn)
{
    using container_attribution::applyAdmittedSet;

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
    using container_attribution::AdmissionPublish;
    using container_attribution::decideAdmissionPublish;

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

TEST(ContainerListRefresh, ASilentSourceAllowsNamedVerdictsWithoutAuthorisingAbsence)
{
    using wazuh::container_instances_client::ContainerDelta;
    using wazuh::container_instances_client::ContainerRef;
    using container_attribution::AdmissionPublish;
    using container_attribution::decideAdmissionPublish;
    using container_attribution::planListRefresh;

    ContainerRef named;
    named.containerId = "a";
    named.cgroupId = 11;
    named.synced = false;
    ContainerDelta delta;
    delta.available = true;
    delta.complete = false;
    delta.sourcesPending = true;
    delta.admittedKnown = true;
    delta.containers = {named};
    const auto plan = planListRefresh(delta, {{"a", true}, {"silent", true}, {"withheld", false}},
    {"a", "silent", "withheld"});

    EXPECT_FALSE(plan.enumerated);
    EXPECT_FALSE(plan.installWholeList);
    EXPECT_EQ(plan.admissionView, (std::map<std::string, bool>
    {{"a", false}, {"silent", true}, {"withheld", false}}));
    ASSERT_EQ(plan.events.size(), 1u);
    EXPECT_NE(plan.events[0].kind, container_attribution::CgroupDeltaEvent::Kind::removed);
    EXPECT_EQ(decideAdmissionPublish(true, false, true, plan.enumerated, delta.sourcesPending),
              AdmissionPublish::install);
    EXPECT_EQ(decideAdmissionPublish(false, true, true, plan.enumerated, delta.sourcesPending),
              AdmissionPublish::install) << "a deferred verdict must install even when the view is unchanged";
    EXPECT_EQ(decideAdmissionPublish(true, false, false, plan.enumerated, delta.sourcesPending),
              AdmissionPublish::defer) << "source readiness does not release the startup walk";
    EXPECT_EQ(decideAdmissionPublish(true, false, true, plan.enumerated), AdmissionPublish::defer)
            << "an old connector still cannot authorise installation";
}
