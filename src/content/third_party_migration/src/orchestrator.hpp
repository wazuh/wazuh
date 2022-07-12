/*
 * Wazuh Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _ORCHESTRATOR_HPP
#define _ORCHESTRATOR_HPP

#include "singleton.hpp"
#include "cmdLineHelper.hpp"
#include <string>
#include <map>

class Orchestrator final : public Singleton<Orchestrator>
{
    public:
        void start(const CmdLineArgs &config) const;
};

#endif // _ORCHESTRATOR_HPP
