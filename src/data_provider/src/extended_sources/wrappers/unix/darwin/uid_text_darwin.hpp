/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <sys/types.h>

/// @brief Reads the text of a UniqueID attribute as a uid.
///
/// The whole text must be a decimal number that fits in 32 bits, with the sign the directory writes
/// for the system accounts (nobody is -2). Anything else, such as an empty value, "4911abc" or
/// "abc", is not a uid: reading its numeric prefix, or zero, would hand the record's data to
/// another account.
///
/// @param text The attribute value.
/// @param uid Output uid, written only when the text is a valid uid.
/// @return True when the text is a valid uid.
inline bool parseUidText(const std::string& text, uid_t& uid)
{
    // strtoll() skips leading white space and would read a bare sign as zero digits, so the first
    // character is checked here.
    if (text.empty() || (!std::isdigit(static_cast<unsigned char>(text[0])) && text[0] != '-' && text[0] != '+'))
    {
        return false;
    }

    errno = 0;
    char* end = nullptr;
    const long long value = std::strtoll(text.c_str(), &end, 10);

    if (end == text.c_str() || *end != '\0' || errno == ERANGE)
    {
        return false;
    }

    if (value < INT32_MIN || value > static_cast<long long>(UINT32_MAX))
    {
        return false;
    }

    uid = static_cast<uid_t>(value);
    return true;
}
