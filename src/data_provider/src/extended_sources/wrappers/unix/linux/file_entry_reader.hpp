/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cerrno>
#include <cstdio>

/// @brief Reads one entry of an account file (such as /etc/passwd or /etc/group) with an
/// fgetpwent_r()/fgetgrent_r() call, so that a line too long for the buffer can be read again.
///
/// Before glibc 2.32 the line is partly read when ERANGE is returned. Going back to its start lets
/// the caller retry the same entry with a larger buffer, as newer glibc does. When the stream
/// cannot go back, EIO is returned instead of ERANGE, so the caller stops instead of reading from
/// the middle of a line.
/// @param stream The stream the read call reads from.
/// @param read The read call, returning 0 or an error number.
/// @return What the read call returned, or EIO as described above.
template<typename Read>
int readFileEntry(FILE* stream, Read&& read)
{
    const auto lineStart = ::ftello(stream);
    const int ret = read();

    if (ret == ERANGE && (lineStart < 0 || ::fseeko(stream, lineStart, SEEK_SET) != 0))
    {
        return EIO;
    }

    return ret;
}
