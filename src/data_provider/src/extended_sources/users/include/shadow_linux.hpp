/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "json.hpp"
#include "ishadow_wrapper.hpp"

/// ShadowProvider class
/// This class is responsible for collecting information from the shadow file.
/// It uses the IShadowWrapper interface to interact with the shadow file.
/// The class provides a method to collect the information and return it in JSON format.
class ShadowProvider
{
    public:
        /// Constructor
        /// @param shadowWrapper A shared pointer to an IShadowWrapper object.
        explicit ShadowProvider(std::shared_ptr<IShadowWrapper> shadowWrapper);

        /// Default constructor
        /// This constructor creates a default ShadowProvider object with a default IShadowWrapper implementation.
        ShadowProvider();

        /// Collects information from the shadow file and returns it in JSON format.
        /// @return A JSON object containing the information collected from the shadow file.
        nlohmann::json collect();

    private:
        /// A shared pointer to an IShadowWrapper object.
        std::shared_ptr<IShadowWrapper> m_shadowWrapper;
};
