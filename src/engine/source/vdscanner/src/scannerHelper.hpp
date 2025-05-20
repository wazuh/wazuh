/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * January 21, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SCANNER_HELPER_HPP
#define _SCANNER_HELPER_HPP

#include "base/utils/stringUtils.hpp"
#include <string>

/**
 * @brief CPE struct.
 */
struct CPE
{
    std::string cpeVersion;   ///< CPE version.
    std::string part;         ///< CPE part.
    std::string vendor;       ///< CPE vendor.
    std::string product;      ///< CPE product.
    std::string version;      ///< CPE version.
    std::string update;       ///< CPE update.
    std::string edition;      ///< CPE edition.
    std::string language;     ///< CPE language.
    std::string swEdition;    ///< CPE software edition.
    std::string targetSw;     ///< CPE target software.
    std::string targetHw;     ///< CPE target hardware.
    std::string other;        ///< CPE other.
    size_t indexQuantity = 0; ///< CPE index quantity.
};

constexpr auto CPE_VERSION_INDEX = 1;

/**
 * @brief CPE fields.
 */
enum CPEFIELDS
{
    part = 1,
    vendor,
    product,
    version,
    update,
    edition,
    language,
    swEdition,
    targetSw,
    targetHw,
    other
};

/**
 * @brief Scanner helper class.
 */
class ScannerHelper final
{
public:
    /**
     * @brief Checks if the string is a CPE.
     *
     * @param value String to check.
     * @return true If the string is a CPE.
     * @return false If the string is not a CPE.
     */
    inline static bool isCPE(const std::string& value) { return base::utils::string::startsWith(value, "cpe:"); }

    /**
     * @brief Parses a CPE string.
     *
     * @param cpeString CPE string.
     * @return CPE Parsed CPE.
     */
    static CPE parseCPE(std::string_view cpeString)
    {
        CPE cpe {};
        std::vector<std::string> cpeParts = base::utils::string::split(cpeString, ':');

        // Check if is 2.2 or 2.3
        // If is 2.2, the first part is "cpe"
        // If is 2.3, the first part is "cpe" and the second part is "2.3"
        const auto offset = base::utils::string::startsWith(cpeString, "cpe:2.3") ? 1 : 0;

        cpe.cpeVersion = offset == 0 ? "2.2" : cpeParts[CPE_VERSION_INDEX];
        cpe.indexQuantity = cpeParts.size() - offset - 1; // -1 because the first part is "cpe"

        const auto maxAvailableIndex {cpeParts.empty() ? 0 : cpeParts.size() - 1};

        if (maxAvailableIndex >= CPEFIELDS::product + offset)
        {
            cpe.part = base::utils::string::leftTrim(cpeParts[CPEFIELDS::part + offset], "/");
            cpe.vendor = cpeParts[CPEFIELDS::vendor + offset];
            cpe.product = cpeParts[CPEFIELDS::product + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::version + offset)
        {
            cpe.version = cpeParts[CPEFIELDS::version + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::update + offset)
        {
            cpe.update = cpeParts[CPEFIELDS::update + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::edition + offset)
        {
            cpe.edition = cpeParts[CPEFIELDS::edition + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::language + offset)
        {
            cpe.language = cpeParts[CPEFIELDS::language + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::swEdition + offset)
        {
            cpe.swEdition = cpeParts[CPEFIELDS::swEdition + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::targetSw + offset)
        {
            cpe.targetSw = cpeParts[CPEFIELDS::targetSw + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::targetHw + offset)
        {
            cpe.targetHw = cpeParts[CPEFIELDS::targetHw + offset];
        }

        if (maxAvailableIndex >= CPEFIELDS::other + offset)
        {
            cpe.other = cpeParts[CPEFIELDS::other + offset];
        }

        return cpe;
    }

    /**
     * @brief CPE comparison.
     *
     * @param cpe1 First CPE.
     * @param cpe2 Second CPE.
     * @return true If the CPEs are equal.
     * @return false If the CPEs are not equal.
     */
    static bool compareCPE(const CPE& cpe1, const CPE& cpe2)
    {
        // Check if the CPEs are equals based on the size of the CPEs
        // Compare to the minor size
        const auto minorSize = std::min(cpe1.indexQuantity, cpe2.indexQuantity);

        if (minorSize == 0)
        {
            return false;
        }

        // Compare the CPEs
        if (minorSize >= CPEFIELDS::part && cpe1.part != "*" && cpe2.part != "*" && cpe1.part != cpe2.part)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::vendor && cpe1.vendor != "*" && cpe2.vendor != "*" && cpe1.vendor != cpe2.vendor)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::product && cpe1.product != "*" && cpe2.product != "*"
            && cpe1.product != cpe2.product)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::version && cpe1.version != "*" && cpe2.version != "*"
            && cpe1.version != cpe2.version)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::update && cpe1.update != "*" && cpe2.update != "*" && cpe1.update != cpe2.update)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::edition && cpe1.edition != "*" && cpe2.edition != "*"
            && cpe1.edition != cpe2.edition)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::language && cpe1.language != "*" && cpe2.language != "*"
            && cpe1.language != cpe2.language)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::swEdition && cpe1.swEdition != "*" && cpe2.swEdition != "*"
            && cpe1.swEdition != cpe2.swEdition)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::targetSw && cpe1.targetSw != "*" && cpe2.targetSw != "*"
            && cpe1.targetSw != cpe2.targetSw)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::targetHw && cpe1.targetHw != "*" && cpe2.targetHw != "*"
            && cpe1.targetHw != cpe2.targetHw)
        {
            return false;
        }

        if (minorSize >= CPEFIELDS::other && cpe1.other != "*" && cpe2.other != "*" && cpe1.other != cpe2.other)
        {
            return false;
        }

        return true;
    }
};

#endif // _SCANNER_HELPER_HPP
