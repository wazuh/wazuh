/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_CLASSIFY_HPP
#define _INDEXER_CLIENT_CLASSIFY_HPP

// curl result → TransportCause (contrato-transport.md §Tipos). Declared in transport.hpp; this header only groups the
// curl-facing helpers so that classify.cpp is the single place that knows curl codes.

#include "transport/transport.hpp"

#endif // _INDEXER_CLIENT_CLASSIFY_HPP
