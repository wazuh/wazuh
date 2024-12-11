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

#include "versionObjectCalVer.hpp"

std::regex VersionObjectCalVer::m_parserRegex(R"((\d{2}|\d{4})(\.\d{1,2})?(\.\d{1,2})?(\.\d+)?)");
