/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef EBPF_WHODATA_H
#define EBPF_WHODATA_H

#include "syscheck.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes the fimebpf instance with pointers to the C functions.
 *
 * @param fim_conf Pointer to fim_configuration_directory.
 * @param getUser Pointer to get_user.
 * @param getGroup Pointer to get_group.
 * @param fimWhodataEvent Pointer to fim_whodata_event.
 * @param freeWhodataEvent Pointer to free_whodata_event.
 * @param loggingFn Pointer to loggingFunction.
 * @param abspathFn Pointer to abspath.
 */
void fimebpf_initialize(directory_t *(*fim_conf)(const char *),
                        char *(*getUser)(int),
                        char *(*getGroup)(int),
                        void (*fimWhodataEvent)(whodata_evt *),
                        void (*freeWhodataEvent)(whodata_evt *),
                        void (*loggingFn)(modules_log_level_t, const char *),
                        char *(*abspathFn)(const char *, char *, size_t),
                        bool (*fimShutdownProcessOn)(),
                        unsigned int syscheckQueueSize);

/**
 * @brief eBPF whodata healthcheck
 *
 * @return err code.
 */
int ebpf_whodata_healthcheck();

/**
 * @brief eBPF whodata function
 *
 * @return err code.
 */
int ebpf_whodata();


int init_libbpf();

int init_bpfobj();


#ifdef __cplusplus
}
#endif // _cplusplus
#endif // EBPF_WHODATA_H
