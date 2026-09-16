/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SHRED_FILE_H
#define SHRED_FILE_H

/**
 * @brief Overwrite every byte of a file with zeros, in the file's own allocation.
 *
 * The file is left in place at its original length; unlinking it is the caller's business.
 *
 * "In its own allocation" is the point of this function, and it is a property of the open rather
 * than of the loop: w_fopen_nofollow_update() opens OPEN_EXISTING / O_RDWR with no truncation on
 * either platform -- the same thing `dd conv=notrunc` gets the POSIX package scripts. An opening
 * mode that truncated would release the original blocks first and write the zeros into a fresh
 * allocation, which is the bug this exists not to have.
 *
 * That helper is also why the open does not follow links. This runs over credential paths, and one
 * caller runs privileged (the MSI custom action, as SYSTEM), so a symlink or hard link swapped in
 * at the target would otherwise be written through -- zeroing whatever it points at rather than
 * the credential.
 *
 * It is not erasure, and nothing that calls it should claim otherwise: a journalling or
 * copy-on-write filesystem, an SSD's remapping layer, a snapshot or a backup can each still hold
 * the old bytes. What it removes is the obvious plaintext copy.
 *
 * @param path File to overwrite. Must already exist.
 * @return 0 when the file's bytes are gone (an already-empty file included), 1 otherwise, having
 *         logged why.
 */
int w_shred_file_in_place(const char *path);

#endif /* SHRED_FILE_H */
