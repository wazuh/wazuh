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
 * "In its own allocation" is the point of this function, and it is a property of the open mode
 * rather than of the loop: wfopen()'s "r+b" is CreateFile(OPEN_EXISTING, GENERIC_READ |
 * GENERIC_WRITE) on Windows and a plain fopen() without O_TRUNC everywhere else -- the same thing
 * `dd conv=notrunc` gets the POSIX package scripts. Opening with "w" would release the original
 * blocks first and write the zeros into a fresh allocation, which is the bug this exists not to
 * have.
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
