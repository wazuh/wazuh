/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef OS_XML_WRAPPERS_H
#define OS_XML_WRAPPERS_H

#include "os_xml/os_xml.h"
#include "../../common.h"


const char * __wrap_w_get_attr_val_by_name(xml_node * node, const char * name) ;


#endif
