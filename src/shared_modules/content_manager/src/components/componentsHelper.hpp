/*
 * Wazuh Content Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 29, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
