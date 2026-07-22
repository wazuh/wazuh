/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_OUTCOME_CLASSIFIER_HPP
#define _HC_OUTCOME_CLASSIFIER_HPP

#include "httpTypes.hpp"

/// D9 classification of one completed attempt. Pure; the full table is
/// enumerated by its unit test. An aborted transfer is always Interrupted,
/// never a silent success (lesson H3 from the in-tree wrapper audit).
OutcomeClass classifyOutcome(const HttpResponse& response);

#endif // _HC_OUTCOME_CLASSIFIER_HPP
