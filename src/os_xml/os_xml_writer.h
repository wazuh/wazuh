/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml C Library.
 * Available at http://www.ossec.net/c/os_xml/
 */


#ifndef OS_XML_WRITER_H
#define OS_XML_WRITER_H

#ifndef XML_MAXSIZE
   #define XML_MAXSIZE          2048
#endif /* XML_MAXSIZE */

#ifndef XML_VAR
   #define XML_VAR              "xml_var"
#endif /* XML_VAR */


/* Error from writer */
#define XMLW_ERROR              006
#define XMLW_NOIN               007
#define XMLW_NOOUT              010


/* OS_WriteXML
 * Write an XML file, based on the input and values to change.
 */
int OS_WriteXML(char *infile, char *outfile, char **nodes, char *attr,
                char *oldval, char *newval,  int type);
  

#endif

/* EOF */
