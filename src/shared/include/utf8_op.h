/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * June 19, 2019
 */

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Return whether a string is UTF-8.
 *
 * @param string File path
 * @return True if the file is UTF-8, false if not.
 */
bool w_utf8_valid(const char * string);


/**
 * @brief Get the pointer to the first character that does not match UTF-8, or the last byte (0).
 *
 * @param string String to be checked.
 * @return Pointer to character.
 */
const char * w_utf8_drop(const char * string);


/**
 * @brief Filter string to remove or replace invalid characters.
 *
 * @param string String to be filtered.
 * @param replacement Set to 0 for remove invalid characters or set to 1 to replace them.
 * @return Return a new string with valid UTF-8 characters only.
 */
char * w_utf8_filter(const char * string, bool replacement);


/**
 * @brief Get the length a string may be cut to without splitting a UTF-8 character.
 *
 * Cutting at a fixed byte offset can fall inside a multi-byte sequence and leave
 * a partial character behind, which is invalid UTF-8. This reports where to stop
 * so the whole trailing sequence is dropped instead. It does not write, so the
 * caller can hand the result to a precision specifier.
 *
 * The string must already be valid UTF-8. A run of continuation bytes longer than
 * any real character cannot be walked back past, so there the cut falls where asked
 * and the result is only as valid as the input was.
 *
 * @param string String to be measured. Must already be valid UTF-8.
 * @param max_length Maximum length in bytes, excluding the null terminator.
 * @return Length in bytes that keeps every character whole, given valid input.
 */
size_t w_utf8_truncate_len(const char * string, size_t max_length);
