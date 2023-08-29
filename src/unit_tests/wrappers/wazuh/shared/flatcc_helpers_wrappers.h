/*
 * Copyright (C) 2015, Wazuh Inc.
 * Aug 29, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FLATCC_HELPERS_WRAPPERS_H
#define FLATCC_HELPERS_WRAPPERS_H

#ifndef WIN32
#ifndef CLIENT

#include "flatcc/flatcc_json_parser.h"
#include "flatcc/flatcc_json_printer.h"

void* __wrap_w_flatcc_parse_json(size_t msg_len, const char* msg, size_t* flatbuffer_size, flatcc_json_parser_flags_t flags, flatcc_json_parser_table_f *parser);

void __wrap_w_flatcc_free_buffer(void* flatbuffer);

char* __wrap_w_flatcc_print_json (void* flatbuffer, size_t flatbuffer_size, size_t *buffer_size, flatcc_json_printer_flags_t flags, flatcc_json_printer_table_f *printer);

#endif /* CLIENT */
#endif /* WIN32 */

#endif // FLATCC_HELPERS_WRAPPERS_H
