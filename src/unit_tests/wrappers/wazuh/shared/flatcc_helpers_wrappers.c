/*
 * Copyright (C) 2015, Wazuh Inc.
 * Aug 29, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef WIN32
#ifndef CLIENT

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "flatcc/flatcc_json_parser.h"
#include "flatcc/flatcc_json_printer.h"

void* __wrap_w_flatcc_parse_json( __attribute__((unused)) size_t msg_len,
                                 const char* msg,
                                 __attribute__((unused)) size_t* flatbuffer_size,
                                 flatcc_json_parser_flags_t flags,
                                 flatcc_json_parser_table_f *parser) {
    check_expected(msg);
    check_expected(flags);
    check_expected(parser);
    return mock_ptr_type(void*);
}

void __wrap_w_flatcc_free_buffer(__attribute__((unused)) void* flatbuffer) {
    function_called();
}

char* __wrap_w_flatcc_print_json (__attribute__((unused)) void* flatbuffer,
                                  __attribute__((unused)) size_t flatbuffer_size,
                                  __attribute__((unused)) size_t *buffer_size,
                                  flatcc_json_printer_flags_t flags,
                                  flatcc_json_printer_table_f *printer) {
    check_expected(flags);
    check_expected(printer);
    return mock_ptr_type(char*);
}

#endif /* CLIENT */
#endif /* WIN32 */
