/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * January 24, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef EBPF_WHODATA_H
#define EBPF_WHODATA_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief eBPF whodata function
 *
 * @param monitored_path Monitored path.
 *
 * @return err code.
 */
int ebpf_whodata(char * monitored_path);

#ifdef __cplusplus
}
#endif // _cplusplus
#endif // EBPF_WHODATA_H
