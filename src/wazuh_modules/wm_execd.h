/*
 * Wazuh EXECD
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 5, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules_def.h"
#include "os_xml/os_xml.h"

#ifndef WM_EXECD_H
#define WM_EXECD_H

#define WM_EXECD_LOGTAG ARGV0 ":execd"  // Tag for log messages

extern const wm_context WM_EXECD_CONTEXT; // Context

typedef void* wm_execd_t;

/**
 * @brief Parses the XML configuration.
 *
 * @param xml     XML file to be parsed.
 * @param node    Specific xml portion to be analyzed.
 * @param modules Current module analyzed.
 * @param module  Module to be initialized.
 *
 * @return 1 if everything was ok, 0 otherwise.
 */
int wm_execd_read(const OS_XML* xml, XML_NODE node, int modules, wmodule* module);

#endif // WM_EXECD_H