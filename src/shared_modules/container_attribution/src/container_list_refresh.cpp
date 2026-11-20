/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_list_refresh.hpp"

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace container_attribution
{

    /* The admission view a list refresh leaves behind.
     *
     * Rebuilt rather than merged: a full list is the whole truth, so a container
     * absent from it is gone, not unchanged.
     *
     * Unless it is NOT the whole truth. container_instances withholds a running
     * container from the list until its resolver can key it, and says so with
     * `withheld`. Treating such a list as authoritative is the worst of the three
     * consumers' versions of the same mistake: it does not merely skip a sweep,
     * it installs an admission set that omits a live container, and
     * fim_container_set_admission() answers "not admitted" for anything missing
     * -- which retracts every one of its sync=1 rows. On a modulesd restart,
     * when the store is cold and the first list is mostly withheld, that is the
     * whole node.
     *
     * So an incomplete list is a set of upserts: what it names is applied, what
     * it omits is left exactly as it was. The caller does the same for the kernel
     * filter, with applyContainerDelta() in place of applyContainerList().
     *
     * Free and pure so the rule can be tested without a connector -- the absence
     * of any seam here is why the drain kept reading a partial list as the whole
     * node long after the other two consumers stopped. */
    /* Record one container's admission, unless the connector has not decided.
     *
     * Every path into the view goes through here, because every one of them
     * carries a flag that DEFAULTS TO TRUE when the reply says nothing:
     * ContainerRef::synced, ContainerEventRef::synced, and the fold of the
     * admitted set. While the verdict is pending the reply deliberately says
     * nothing on all three, so taking the defaults writes "admitted" over
     * refusals the connector is about to re-issue -- which is what made a
     * modulesd restart re-admit containers it had correctly refused, create
     * their documents on the manager, and delete them again seconds later.
     *
     * Pending therefore FREEZES what is already known and holds anything new at
     * not-admitted. Both halves matter: keeping a stored decision is what stops
     * the restart churn, and holding a newcomer back is what stops the node
     * reporting past containers.synced_limit for the length of the window.
     * Erring towards not-admitted is the recoverable direction -- a container
     * held back for a few seconds is promoted when the verdict lands, while one
     * let through has already had its documents created. */
    namespace
    {
    void setAdmission(std::map<std::string, bool>& view,
                      const std::string& containerId,
                      bool admitted,
                      bool admissionPending)
    {
        if (admissionPending)
        {
            view.emplace(containerId, false); /* Only if absent; never overwrites. */
            return;
        }

        view[containerId] = admitted;
    }
    } // namespace

    std::map<std::string, bool> mergeAdmissionView(
        const std::map<std::string, bool>& current,
        const std::vector<wazuh::container_instances_client::ContainerRef>& refs,
        bool complete,
        bool admissionPending)
    {
        std::map<std::string, bool> refreshed;

        if (!complete)
        {
            refreshed = current;
        }

        for (const auto& ref : refs)
        {
            setAdmission(refreshed, ref.containerId, ref.synced, admissionPending);
        }

        return refreshed;
    }

    /* Fold the connector's whole admitted set into a view built from events.
     *
     * The lifecycle stream carries admission only for containers that HAVE an
     * event, and recomputeAdmittedLocked() moves it for containers that do not:
     * readmit one because another freed a slot under containers.synced_limit,
     * and no event is journalled for it. A view merged from events alone
     * therefore keeps a readmitted container withheld, or keeps reporting one
     * the cap has since pushed out.
     *
     * Positive always, negative only from a reply that ENUMERATES. Membership
     * in the set is the connector's own answer and can be taken at once;
     * absence from it means "not admitted" only once the reply has named every
     * container that exists, because until then absence is indistinguishable
     * from a container the reply did not get to and withdrawing it would
     * retract a live container's rows.
     *
     * Enumerating is not the same as having keyed them all. The connector ranks
     * a container it cannot key along with the rest and names it in
     * `known_unkeyed`, so a reply that carries that key has accounted for every
     * container even though `complete` is false. Gating this on `complete`
     * meant a single container nobody can key -- or any container for the
     * seconds after it restarts -- held every withdrawal on this path for as
     * long as it stayed unkeyed: lower containers.synced_limit and the drain
     * went on republishing as admitted the containers the baseline had just
     * retracted, which alternated their documents between CREATE and DELETE. */
    void applyAdmittedSet(std::map<std::string, bool>& view,
                          const std::set<std::string>& admitted,
                          bool admittedKnown,
                          bool enumerated)
    {
        if (!admittedKnown)
        {
            return; /* A server too old to send it; leave the view as it was. */
        }

        for (auto& [containerId, isAdmitted] : view)
        {
            if (admitted.count(containerId) != 0)
            {
                isAdmitted = true;
            }
            else if (enumerated)
            {
                isAdmitted = false;
            }
        }
    }

    /* Put the containers the connector could not key into the view, with the
     * decision it made about them.
     *
     * They are containers, so the cap ranks them, so they are in `admitted` or
     * refused like anything else -- they simply have no record in the reply to
     * carry a `synced` flag, and the whole set is where their answer lives.
     * Keeping them beside the view as an unrankable third category is what let
     * a container report outside containers.synced_limit for as long as it was
     * unkeyed, which is a window every restart opens.
     *
     * A server too old to send the set leaves no decision to read, and reading
     * silence as a refusal would retract live rows: admit them, as this did
     * before the set existed. */
    namespace
    {
    void foldUnkeyedIntoView(std::map<std::string, bool>& view,
                             const std::set<std::string>& unkeyed,
                             const std::set<std::string>& admitted,
                             bool admittedKnown,
                             bool admissionPending)
    {
        for (const auto& containerId : unkeyed)
        {
            setAdmission(view, containerId, !admittedKnown || admitted.count(containerId) != 0, admissionPending);
        }
    }
    } // namespace

    /* Two reasons to hold an admission snapshot back, and one trap in holding it.
     *
     * not released  installing runs a reconciliation that reads and writes
     *               file_entry, and the baseline walk's scoped transaction is
     *               open until release. Same hazard
     *               fim_container_events_release() exists for.
     * not enumerated  an older connector cannot describe what it left out.
     *                 A current connector can instead say a source is silent:
     *                 its named verdicts may be installed with that coverage
     *                 flag, so the bridge keeps omitted ids unknown rather
     *                 than retracting documents it has no verdict against.
     *
     * What this deliberately does NOT wait for is every container to be KEYED.
     * It used to, and a container whose cgroup no process reports never is, so
     * the snapshot was never installed again and every container that started
     * afterwards read as refused for the life of the process. An
     * unkeyed container has an id, which is all admission needs; only the
     * cgroup map needs the key.
     *
     * The trap: the caller records the new view whether or not it installs it,
     * so "publish when it next CHANGES" silently means never on a quiet node --
     * the change has already been absorbed. `unpublished` is what remembers
     * that the installed snapshot is behind the view, so the next call that can
     * install does, with or without a further change. */
    AdmissionPublish decideAdmissionPublish(bool changed, bool unpublished, bool released, bool enumerated,
                                            bool sourcesPending)
    {
        if (!changed && !unpublished)
        {
            return AdmissionPublish::nothing;
        }

        if (!released || (!enumerated && !sourcesPending))
        {
            return AdmissionPublish::defer;
        }

        return AdmissionPublish::install;
    }

    ListRefreshPlan planListRefresh(const wazuh::container_instances_client::ContainerDelta& delta,
                                    const std::map<std::string, bool>& currentView,
                                    const std::set<std::string>& mappedContainers,
                                    const std::set<std::string>& previousUnkeyed)
    {
        ListRefreshPlan plan;
        plan.complete = delta.complete;

        /* Keyed-complete and enumerated are different claims, and only the
         * second is what admission needs. A connector too old to report its
         * unkeyed ids leaves `complete` as the only evidence either way. */
        plan.enumerated = delta.complete || delta.unkeyedKnown;

        /* Handed straight back so the caller can compare against it next time.
         * Only when the reply can enumerate: otherwise the set is empty for
         * want of a connector that reports it, not for want of containers, and
         * keeping the previous one is what stops that reading as a departure. */
        if (plan.enumerated)
        {
            plan.unkeyed = delta.unkeyed;
        }
        else
        {
            plan.unkeyed = previousUnkeyed;
        }

        /* unreachable: nothing was obtained. Keep the map -- install()
         * replaces the positive map, so applying an empty list from a connector
         * that simply did not answer would un-attribute every container at once
         * and turn the next event from each into an escalation. */
        if (!delta.available)
        {
            return plan;
        }

        plan.act = true;

        /* deltas unsupported: an older container_instances, which ignored the
         * cursor and answered with the set.
         * resync required:    the cursor is from another store lifetime, or its
         *                     position has been evicted. The set rides the same
         *                     reply, so this costs no extra round trip. */
        if (!delta.deltaSupported || delta.resyncRequired)
        {
            plan.installWholeList = delta.complete;
            plan.containers.reserve(delta.containers.size());

            if (!delta.complete)
            {
                plan.events.reserve(delta.containers.size());
            }

            for (const auto& ref : delta.containers)
            {
                plan.containers.emplace_back(ref.cgroupId, ref.containerId);

                if (!delta.complete)
                {
                    /* applyDelta() withdraws whatever THIS container held before
                     * applying the event, and touches no other container --
                     * which is precisely the difference from install(), and the
                     * whole reason a partial reply may be applied at all. */
                    CgroupDeltaEvent upsert;
                    upsert.kind             = CgroupDeltaEvent::Kind::changed;
                    upsert.cgroup_id        = ref.cgroupId;
                    upsert.container_id     = ref.containerId;
                    upsert.extra_cgroup_ids = ref.extraCgroupIds;
                    plan.events.push_back(std::move(upsert));
                }

                /* Every other cgroup the container occupies, as its own entry. A
                 * container running an init system has one per unit, and the
                 * kernel filter matches an event's cgroup id by equality -- so a
                 * key that does not reach the allowlist is a unit whose file
                 * events are discarded before anything downstream can see them.
                 *
                 * One entry per key rather than a key set in the map, because the
                 * map is keyed by inode precisely because that is what every
                 * event carries; attribution then needs no second lookup. */
                for (const auto extra : ref.extraCgroupIds)
                {
                    plan.containers.emplace_back(extra, ref.containerId);
                }
            }

            /* install() would have removed what the list omits, but it cannot be
             * used here: it replaces the map, and this reply has no cgroup id
             * for the containers it could not key, so installing it would drop
             * their entries and turn their next event into an escalation.
             *
             * Upserts alone never remove anything, though -- so a container
             * that went away while the cursor was invalid kept its cgroups in
             * the map, and allowed in the kernel, for as long as the node held
             * one container nobody could key. The inode is then free for the
             * kernel to hand to something else, and whatever lands on it is
             * filed under a container that no longer exists.
             *
             * The reply does say which containers EXIST, so name the departures
             * one by one. A `removed` event withdraws every cgroup that
             * container held, which is what install() would have done for it.
             * Only when the reply enumerates: without that there is no
             * difference between "gone" and "not mentioned". */
            std::set<std::string> present = delta.unkeyed;

            for (const auto& ref : delta.containers)
            {
                present.insert(ref.containerId);
            }

            if (!plan.installWholeList && plan.enumerated)
            {
                for (const auto& containerId : mappedContainers)
                {
                    if (present.count(containerId) != 0)
                    {
                        continue;
                    }

                    CgroupDeltaEvent gone;
                    gone.kind         = CgroupDeltaEvent::Kind::removed;
                    gone.container_id = containerId;
                    plan.events.push_back(std::move(gone));
                }
            }

            plan.admissionView =
                mergeAdmissionView(currentView, delta.containers, delta.complete, delta.admissionPending);
            foldUnkeyedIntoView(
                plan.admissionView, delta.unkeyed, delta.admitted, delta.admittedKnown, delta.admissionPending);

            /* ...and the same departures leave the admission view, for the same
             * reason and with the same guard.
             *
             * A complete reply needs none of this: mergeAdmissionView() rebuilds
             * the view from the reply alone and what is gone is simply not in it.
             * An INCOMPLETE one merges, so it only ever adds -- and a container
             * that went away while the cursor was invalid stayed in the view for
             * the life of the process, because nothing else removes from it on
             * this path. The delta path below erases on a `removed` event and
             * says why: a view that only grows grows without bound on a host
             * that churns containers.
             *
             * It is not only size. A departed container keeps answering
             * fim_container_is_admitted(), so it holds its place in the set the
             * drain publishes, and its id reads as known rather than unheard-of
             * if the runtime ever reuses it. */
            if (!delta.complete && plan.enumerated)
            {
                for (auto it = plan.admissionView.begin(); it != plan.admissionView.end();)
                {
                    if (present.count(it->first) == 0)
                    {
                        it = plan.admissionView.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            applyAdmittedSet(plan.admissionView, delta.admitted, delta.admittedKnown, plan.enumerated);
            return plan;
        }

        plan.events.reserve(delta.events.size());

        for (const auto& event : delta.events)
        {
            CgroupDeltaEvent translated;
            translated.container_id     = event.containerId;
            translated.cgroup_id        = event.cgroupId;
            translated.extra_cgroup_ids = event.extraCgroupIds;

            switch (event.kind)
            {
                    using Kind = wazuh::container_instances_client::ContainerEventRef::Kind;

                case Kind::added:
                    translated.kind = CgroupDeltaEvent::Kind::added;
                    break;

                case Kind::removed:
                    translated.kind = CgroupDeltaEvent::Kind::removed;
                    break;

                case Kind::changed:
                default:
                    translated.kind = CgroupDeltaEvent::Kind::changed;
                    break;
            }

            plan.events.push_back(std::move(translated));
        }

        /* Merged into the view rather than rebuilt from it: a delta describes
         * transitions, so a container it does not mention is unchanged, not
         * gone. `added` and `changed` carry the connector's current answer for
         * that container; `removed` carries no record, and a container that no
         * longer exists needs no admission -- dropping it also keeps the view
         * from growing without bound on a host that churns containers. */
        std::map<std::string, bool> updated {currentView};

        /* Retire the unkeyed containers this reply no longer names.
         *
         * An unkeyed container reaches the view from the LIST side, through
         * foldUnkeyedIntoView() below, and no event can ever take it out again:
         * the store erases a record that never had a key WITHOUT journalling,
         * because a container that was never published has no visibility
         * transition for consumers to act on, so no `removed` is emitted. The
         * id therefore sat in the view for the life of the process -- the
         * unbounded growth an incomplete resync used to have, reached by the
         * other path, and with the same consequence beyond size: a departed
         * container goes on answering fim_container_is_admitted() and its id
         * reads as known rather than unheard-of if the runtime reuses it.
         *
         * Before the events, not after: one that has merely been KEYED since
         * the last reply is named by this one, so its event puts it straight
         * back with an attribution key this time. */
        if (plan.enumerated)
        {
            for (const auto& containerId : previousUnkeyed)
            {
                if (delta.unkeyed.count(containerId) == 0)
                {
                    updated.erase(containerId);
                }
            }
        }

        for (const auto& event : delta.events)
        {
            if (event.containerId.empty()) continue;

            using Kind = wazuh::container_instances_client::ContainerEventRef::Kind;

            if (event.kind == Kind::removed)
            {
                updated.erase(event.containerId);
            }
            else
            {
                setAdmission(updated, event.containerId, event.synced, delta.admissionPending);
            }
        }

        /* ...then the containers no event can describe, because the connector
         * cannot key them... */
        foldUnkeyedIntoView(updated, delta.unkeyed, delta.admitted, delta.admittedKnown, delta.admissionPending);

        /* ...and then the set, which is the only place an admission change with
         * no event of its own can reach this view. */
        applyAdmittedSet(updated, delta.admitted, delta.admittedKnown, plan.enumerated);

        plan.admissionView = std::move(updated);
        return plan;
    }

} // namespace container_attribution
