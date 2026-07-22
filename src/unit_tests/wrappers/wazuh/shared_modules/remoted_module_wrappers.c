/*
 * Wazuh remoted_module wrappers
 * Copyright (C) 2015, Wazuh Inc.
 * July 22, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * The C++ remoted module ships as its own shared library (libremoted_module.so) and is
 * reached from remoted's C code (secure.c) through the extern "C" entry points
 * remoted_module_start()/remoted_module_stop(). The legacy C unit tests link the static
 * libremoted_lib.a (which contains secure.c) but not that shared library, so these two
 * symbols would be undefined. They are mocked here as no-ops (via -Wl,--wrap) so the
 * remoted tests link without pulling in the whole HTTPS/auth module and without starting
 * its worker thread. Signatures are kept source-compatible with include/remoted_module.h
 * without depending on that header (only the symbol names matter to the linker).
 */

#include <stdarg.h>

typedef void (*full_log_fnc_t)(int level,
                               const char* tag,
                               const char* file,
                               int line,
                               const char* func,
                               const char* msg,
                               va_list args);

void __wrap_remoted_module_start(full_log_fnc_t callback_log, const void* configuration)
{
    (void)callback_log;
    (void)configuration;
}

void __wrap_remoted_module_stop(void)
{
}
