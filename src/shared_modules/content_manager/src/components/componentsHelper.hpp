/*
 * Wazuh Content Manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _COMPONENTS_HELPER_HPP
#define _COMPONENTS_HELPER_HPP

#include <string>

namespace Components
{
    namespace Columns
    {
        /**
         * @brief Column holding the change-detection token.
         *
         * Named `current_offset` for continuity: it predates the token abstraction and renaming it
         * would orphan every already-deployed updater database for no gain.
         */
        static const std::string CURRENT_OFFSET {"current_offset"};
    } // namespace Columns
} // namespace Components

#endif // _COMPONENTS_HELPER_HPP
