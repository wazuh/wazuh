/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * November 3, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "versionObjectPEP440.hpp"

/**
 * @brief Regular expression pattern for auxiliary parsing PEP 440 version strings.
 *
 */
std::regex VersionObjectPEP440::m_parserVersionStrRegex(R"(\.)");
