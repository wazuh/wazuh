/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_XML_WRAPPERS_H
#define OS_XML_WRAPPERS_H

#include "../../common.h"
#include "os_xml.h"

const char* __wrap_w_get_attr_val_by_name(xml_node* node, const char* name);
void __wrap_OS_ClearXML(OS_XML* _lxml) __attribute__((nonnull));
int __wrap_OS_ReadXML(const char* file, OS_XML* lxml) __attribute__((nonnull));
int __wrap_OS_ReadXML_Ex(const char* file, OS_XML* lxml) __attribute__((nonnull));

#endif
