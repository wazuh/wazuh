/*
 * Wazuh HTTPS communications
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _HTTPS_HEADER_LINE_HPP
#define _HTTPS_HEADER_LINE_HPP

#include <cstddef>

/// Size limit of the JSON in the H line that opens every /stateless body. remoted rejects a
/// larger one together with the whole batch, and the agent trims its H line to fit, so both
/// read it from here.
constexpr std::size_t HTTPS_HEADER_LINE_JSON_MAX_BYTES = 8 * 1024;

#endif // _HTTPS_HEADER_LINE_HPP
