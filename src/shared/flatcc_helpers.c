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

#ifndef WIN32
#ifndef CLIENT

#include "flatcc_helpers.h"
#include "flatcc/flatcc_json_parser.h"
#include "flatcc/flatcc_json_printer.h"
#include "debug_op.h"

void* w_flatcc_parse_json(size_t msg_len, const char* msg, size_t* flatbuffer_size, flatcc_json_parser_flags_t flags, flatcc_json_parser_table_f *parser) {

    flatcc_builder_t builder;
    if(flatcc_builder_init(&builder)) {
        mdebug1("Failed to initialize flatcc structure.");
        return NULL;
    }

    flatcc_json_parser_t parser_ctx;
    int err_code = flatcc_json_parser_table_as_root(&builder, &parser_ctx, msg, msg_len, flags, NULL, parser);
    if (err_code) {
        mdebug2("Failed to parse message with flatbuffer schema: %s", flatcc_json_parser_error_string(err_code));
        return NULL;
    } else {
        return flatcc_builder_finalize_aligned_buffer(&builder, flatbuffer_size);
    }
}

void w_flatcc_free_buffer(void* flatbuffer) {
    flatcc_builder_aligned_free(flatbuffer);
}

char* w_flatcc_print_json (void* flatbuffer, size_t flatbuffer_size, size_t *buffer_size, flatcc_json_printer_flags_t flags, flatcc_json_printer_table_f *printer) {
    flatcc_json_printer_t printer_ctx;
    flatcc_json_printer_init_dynamic_buffer(&printer_ctx, 0);
    flatcc_json_printer_set_flags(&printer_ctx, flags);

    flatcc_json_printer_table_as_root(&printer_ctx, flatbuffer, flatbuffer_size, NULL, printer);

    return flatcc_json_printer_finalize_dynamic_buffer(&printer_ctx, buffer_size);
}

#endif /* CLIENT */
#endif /* WIN32 */
