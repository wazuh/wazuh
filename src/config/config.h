/*   $OSSEC, config.h, v0.1, 2006/04/06, Daniel B. Cid$   */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 

#ifndef _HCONFIG__H
#define _HCONFIG__H

#define CGLOBAL      0000001
#define CRULES       0000002
#define CSYSCHECK    0000004
#define CROOTCHECK   0000010
#define CALERTS      0000020
#define CLOCALFILE   0000040
#define CREMOTE      0000100
#define CCLIENT      0000200
#define CMAIL        0000400

#include "os_xml/os_xml.h"

/* Main function to read the config */
int ReadConfig(int modules, char *cfgfile, void *d1, void *d2);

int Read_Global(XML_NODE node, void *d1, void *d2);
int Read_Rules(XML_NODE node, void *d1, void *d2);
int Read_Syscheck(XML_NODE node, void *d1, void *d2);
int Read_Rootcheck(XML_NODE node, void *d1, void *d2);
int Read_Alerts(XML_NODE node, void *d1, void *d2);
int Read_Localfile(XML_NODE node, void *d1, void *d2);
int Read_Remote(XML_NODE node, void *d1, void *d2);
int Read_Client(XML_NODE node, void *d1, void *d2);



#endif
