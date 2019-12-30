#ifndef __WMODULES_SCHEDULING_HELPERS_H__
#define __WMODULES_SCHEDULING_HELPERS_H__

#include "shared.h"

const XML_NODE string_to_xml_node(const char * string, OS_XML *_lxml);
sched_scan_config init_config_from_string(const char* string);

#endif