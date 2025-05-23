/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ishadow_wrapper.hpp"

/// ShadowWrapper class
/// This class is responsible for providing an interface to the shadow file functions.
class ShadowWrapper : public IShadowWrapper
{
    public:
        /// @brief lckpwdf locks the shadow file
        /// @return Returns 0 on success, -1 on error
        int lckpwdf()
        {
            return ::lckpwdf();
        }

        /// @brief setspent sets the position of the shadow file to the beginning
        void setspent()
        {
            return ::setspent();
        }

        /// @brief getspent reads the next entry from the shadow file
        /// @return Returns a pointer to the next entry in the shadow file
        struct spwd* getspent()
        {
            return ::getspent();
        }

        /// @brief endspent closes the shadow file
        void endspent()
        {
            return ::endspent();
        }

        /// @brief ulckpwdf unlocks the shadow file
        /// @return Returns 0 on success, -1 on error
        int ulckpwdf()
        {
            return ::ulckpwdf();
        }

};
