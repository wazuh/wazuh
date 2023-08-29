/*
 * Flatcc helpers.
 * Copyright (C) 2015, Wazuh Inc.
 * Aug 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FLATCC_HELPERS_H
#define FLATCC_HELPERS_H

#ifndef WIN32
#ifndef CLIENT

#include "flatcc/flatcc_json_parser.h"
#include "flatcc/flatcc_json_printer.h"

/**
 * @brief
 *
 * @param msg_len
 * @param msg
 * @param flatbuffer_size
 * @param flags
 * @param parser
 * @return void*
 */
void* w_flatcc_parse_json(size_t msg_len, const char* msg, size_t* flatbuffer_size, flatcc_json_parser_flags_t flags, flatcc_json_parser_table_f *parser);

/**
 * @brief
 *
 * @param flatbuffer
 */
void w_flatcc_free_buffer(void* flatbuffer);

/**
 * @brief
 *
 * @param flatbuffer
 * @param flatbuffer_size
 * @param buffer_size
 * @param flags
 * @param printer
 * @return char*
 */
char* w_flatcc_print_json (void* flatbuffer, size_t flatbuffer_size, size_t *buffer_size, flatcc_json_printer_flags_t flags, flatcc_json_printer_table_f *printer);

#endif /* CLIENT */
#endif /* WIN32 */
#endif /* FLATCC_HELPERS_H */
