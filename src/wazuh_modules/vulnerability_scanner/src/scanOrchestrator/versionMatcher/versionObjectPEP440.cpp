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
 * @brief Regular expression pattern for parsing PEP 440 version strings.
 *
 * @details This regex is used to parse PEP 440 version strings. It supports the alternative syntax as well as the
 * canonical form.
 *
 * Capture groups:
 * - 1: Epoch
 * - 2: Release version string
 * - 3: Pre-release string: a, b, c, rc, alpha, beta, pre, preview
 * - 4: Pre-release number
 * - 5: Implicit post release number
 * - 6: Post-release string: post, r, rev
 * - 7: Post-release number
 * - 8: Development release string: dev
 * - 9: Development release number
 *
 * This regex is case-insensitive.
 */
std::regex VersionObjectPEP440::m_parserRegex(
    R"(^v?(?:(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[-_\.]?(a|b|c|rc|alpha|beta|pre|preview)[-_\.]?([0-9]+)?)?(?:(?:-([0-9]+))|(?:[-_\.]?(post|rev|r)[-_\.]?([0-9]+)?))?(?:[-_\.]?(dev)[-_\.]?([0-9]+)?)?)?$)",
    std::regex_constants::icase);

std::regex VersionObjectPEP440::m_parserVersionStrRegex(R"(\.)");
