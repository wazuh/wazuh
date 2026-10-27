/*
 * Wazuh Syscheckd — comparing container identities across list refreshes
 * (#37532).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License (version 2) as published
 * by the FSF - Free Software Foundation.
 */

#ifndef _CONTAINER_IDENTITY_SET_HPP
#define _CONTAINER_IDENTITY_SET_HPP

#include <set>
#include <string>

namespace fim_container_events
{

using ContainerIdentitySet = std::set<std::string>;

inline bool ContainerIdentitySetChanged(const ContainerIdentitySet& previous,
                                       const ContainerIdentitySet& current)
{
    return previous != current;
}

} // namespace fim_container_events

#endif /* _CONTAINER_IDENTITY_SET_HPP */
