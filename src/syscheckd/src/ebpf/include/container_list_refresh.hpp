/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 * GPLv2.
 */

#ifndef _CONTAINER_LIST_REFRESH_HPP
#define _CONTAINER_LIST_REFRESH_HPP

#include "cgroup_container_map.hpp"
#include "container_instances_client.hpp"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

/* What the drain does with one container_instances list reply, decided apart
 * from doing it.
 *
 * The drain reads that reply on its resolver thread and turns it into two side
 * effects: the kernel cgroup allowlist, and the admission snapshot the FIM
 * bridge reconciles against. Both are reached through a pimpl with a live
 * socket behind it, so for a long time nothing here could be tested at all --
 * and every rule in it was learned the same way, by shipping it wrong:
 *
 *   - a partial reply read as the whole node, which retracted live containers
 *   - admission tracked from lifecycle events alone, which never hear about a
 *     container readmitted when another freed a slot
 *   - a snapshot deferred before the walk released and then never installed,
 *     because the view it was compared against had already absorbed it
 *   - that deferral made permanent by a container nobody can key, which held
 *     the single completeness flag false for as long as it ran
 *   - a resync that could not be installed wholesale leaving the cgroups of
 *     departed containers in the map, and allowed in the kernel, for ever
 *
 * So the decision is a pure function over the reply and the current view, and
 * the drain is left executing a plan it did not have to think about.
 */
namespace fim_container_events
{
    /// Everything one list reply asks the drain to do.
    struct ListRefreshPlan
    {
        /// The connector answered. False leaves EVERYTHING alone, cursor
        /// included: an unanswered query is not an empty node.
        bool act {false};

        /// Replace the cgroup map wholesale (install) rather than upsert into
        /// it (applyDelta). Only ever true for a reply that covers every
        /// container, because install() removes what the list omits.
        bool installWholeList {false};

        /// The map to install, when installWholeList.
        std::vector<std::pair<std::uint64_t, std::string>> containers;

        /// The transitions to apply otherwise -- translated lifecycle events,
        /// or one upsert per container of a partial full list.
        std::vector<CgroupDeltaEvent> events;

        /// The admission view this reply leaves behind: every container it
        /// named, keyed or not, and whether the cap admitted each. A container
        /// with no attribution key is still ranked -- the cap bounds how many
        /// containers report, which is a question about ids -- so it belongs
        /// here and not in a category of its own. It must still stay out of
        /// `containers` and `events`: an id with no cgroup id cannot reach the
        /// map.
        std::map<std::string, bool> admissionView;

        /// Whether every container in the reply is KEYED. Gates the cgroup map
        /// only: install() removes what the list omits, and an unkeyed
        /// container has no cgroup id to put there in the first place.
        bool complete {false};

        /// Whether the reply names every container that EXISTS, keyed or not.
        /// Gates the admission snapshot, which decides who may report and never
        /// touches an attribution key. These were one flag until a container
        /// nobody could key held `complete` false for as long as it ran and
        /// froze admission for the whole node.
        bool enumerated {false};
    };

    /// What to do with an admission view the drain has just recomputed.
    enum class AdmissionPublish
    {
        nothing, ///< identical to what is already installed
        defer,   ///< hold it: not safe to install, or not the whole node yet
        install
    };

    /// @brief Decide one list reply's effects against the state the drain holds.
    ///
    /// @param mappedContainers Which containers the cgroup map currently holds
    ///        entries for. Needed because a reply that names every container but
    ///        keys only some of them cannot be installed wholesale, and the
    ///        departures then have to be named one by one -- without that, a
    ///        container that went away while the cursor was invalid keeps its
    ///        cgroups in the map, and allowed in the kernel, for ever.
    [[nodiscard]] ListRefreshPlan planListRefresh(const wazuh::container_instances_client::ContainerDelta& delta,
                                                  const std::map<std::string, bool>& currentView,
                                                  const std::set<std::string>& mappedContainers = {});

    /// @brief The admission view a full list leaves behind.
    [[nodiscard]] std::map<std::string, bool> mergeAdmissionView(
        const std::map<std::string, bool>& current,
        const std::vector<wazuh::container_instances_client::ContainerRef>& refs,
        bool complete);

    /// @brief Fold the connector's whole admitted set into a view built from events.
    void applyAdmittedSet(std::map<std::string, bool>& view,
                          const std::set<std::string>& admitted,
                          bool admittedKnown,
                          bool complete);

    /// @brief Whether an admission snapshot may be installed now, held, or ignored.
    [[nodiscard]] AdmissionPublish decideAdmissionPublish(bool changed,
                                                          bool unpublished,
                                                          bool released,
                                                          bool enumerated);

} // namespace fim_container_events

#endif // _CONTAINER_LIST_REFRESH_HPP
