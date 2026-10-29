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
 *   R1  a partial reply read as the whole node, which retracted live
 *       containers
 *   R3  admission tracked from lifecycle events alone, which never hear about
 *       a container readmitted when another freed a slot
 *   R5  a snapshot deferred before the walk released and then never installed,
 *       because the view it was compared against had already absorbed it
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

        /// The admission view this reply leaves behind.
        std::map<std::string, bool> admissionView;

        /// Whether the reply covered every running container. Carried through
        /// because installing an admission snapshot built from a partial reply
        /// marks the containers it omits as refused rather than unheard-of.
        bool complete {false};
    };

    /// What to do with an admission view the drain has just recomputed.
    enum class AdmissionPublish
    {
        nothing, ///< identical to what is already installed
        defer,   ///< hold it: not safe to install, or not the whole node yet
        install
    };

    /// @brief Decide one list reply's effects against the view the drain holds.
    [[nodiscard]] ListRefreshPlan planListRefresh(const wazuh::container_instances_client::ContainerDelta& delta,
                                                  const std::map<std::string, bool>& currentView);

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
                                                          bool complete);

} // namespace fim_container_events

#endif // _CONTAINER_LIST_REFRESH_HPP
