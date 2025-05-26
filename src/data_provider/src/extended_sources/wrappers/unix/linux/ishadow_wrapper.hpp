/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <shadow.h>

// Interface for the shadow wrapper
class IShadowWrapper
{
    public:
        /// Destructor
        virtual ~IShadowWrapper() = default;

        /// @brief lckpwdf locks the shadow file
        /// @return Returns 0 on success, -1 on error
        virtual int lckpwdf() = 0;

        /// @brief setspent sets the position of the shadow file to the beginning
        virtual void setspent() = 0;

        /// @brief getspent reads the next entry from the shadow file
        /// @return Returns a pointer to the next entry in the shadow file
        virtual spwd* getspent() = 0;

        /// @brief endspent closes the shadow file
        virtual void endspent() = 0;

        /// @brief ulckpwdf unlocks the shadow file
        /// @return Returns 0 on success, -1 on error
        virtual int ulckpwdf() = 0;
};
