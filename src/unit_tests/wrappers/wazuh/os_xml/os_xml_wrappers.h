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

#include "../os_xml/os_xml.h"
#include "../../common.h"

const char * __wrap_w_get_attr_val_by_name(xml_node * node, const char * name);
xml_node ** __wrap_OS_GetElementsbyNode(const OS_XML * _lxml, const xml_node * node) __attribute__((nonnull(1)));
void __wrap_OS_ClearNode(xml_node ** node);
void __wrap_OS_ClearXML(OS_XML * _lxml) __attribute__((nonnull));
int __wrap_OS_ReadXML(const char * file, OS_XML * lxml) __attribute__((nonnull));
int __wrap_OS_ReadXML_Ex(const char * file, OS_XML * lxml) __attribute__((nonnull));
int __wrap_OS_ReadXMLString(const char * file, OS_XML * lxml) __attribute__((nonnull));

#endif
