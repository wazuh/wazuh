/*   $OSSEC, os_xml.h, v0.2, 2005/02/10, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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


#ifndef __OS_XML_H
#define __OS_XML_H

#ifndef XML_MAXSIZE
   #define XML_MAXSIZE          1024
#endif /* XML_MAXSIZE */

#ifndef XML_VAR
   #define XML_VAR              "xml_var"
#endif /* XML_VAR */

#define XML_ELEM                101
#define XML_ATTR                102
#define XML_VARIABLE_BEGIN      '$'

/* XML Node structure */
typedef struct _xml_node
{
    int key;
    int line;
    char *element;
    char *content;
    char **attributes;
    char **values;
}xml_node;

/* XML structure */
typedef struct _OS_XML
{
    int cur;		/* Currently position (and last after reading) */
    int fol;		/* Currently position for the xml_access */
    int *tp;		/* Item type	*/
    int *rl;		/* Relation in the XML */
    int *ck;		/* If the item was closed or not */
    int *ln;        /* Currently xml file line */
    char **ct;		/* Content is stored */
    char **el;		/* The element/attribute name is stored */
    char err[128];	/* Error messages are stored in here */
}OS_XML;

typedef xml_node ** XML_NODE;

/* Start the XML structure reading a file */
int OS_ReadXML(char *file, OS_XML *lxml);

/* Clear the XML strucute memory */
void OS_ClearXML(OS_XML *_lxml);

/* clear a node */
void OS_ClearNode(xml_node **node);


/* Functions to read the XML */

/* Return 1 if element_name is a root element */
int OS_RootElementExist(OS_XML *_lxml, char *element_name);

/* Return 1 if the element_name exists */
int OS_ElementExist(OS_XML *_lxml, char **element_name);

/* Return the elements "children" of the element_name */
char **OS_GetElements(OS_XML *_lxml, char **element_name);

/* Return the elements "children" of the element_name */
xml_node **OS_GetElementsbyNode(OS_XML *_lxml, xml_node *node);

/* Return the attributes of the element name */
char **OS_GetAttributes(OS_XML *_lxml, char **element_name);

/* Return one value from element_name */
char *OS_GetOneContentforElement(OS_XML *_lxml, char **element_name);

/* Return an array with the content of all entries of element_name */
char **OS_GetElementContent(OS_XML *_lxml, char **element_name);

/* Return an array with the contents of an element_nane */
char **OS_GetContents(OS_XML *_lxml, char **element_name);

/* Return the value of a specific attribute of the element_name */
char *OS_GetAttributeContent(OS_XML *_lxml, char **element_name,
        char *attribute_name);

/* Apply the variables to the xml */
int OS_ApplyVariables(OS_XML *_lxml);

#endif

/* EOF */
