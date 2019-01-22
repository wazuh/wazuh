/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml C Library */

#ifndef __OS_XML_H
#define __OS_XML_H

#include <stdio.h>

/* XML Node structure */
typedef struct _xml_node {
    unsigned int key;
    char *element;
    char *content;
    char **attributes;
    char **values;
} xml_node;

#define XML_ERR_LENGTH  128
#define XML_STASH_LEN   2
#define xml_getc_fun(x,y) (x)? _xml_fgetc(x,y) : _xml_sgetc(y)
typedef enum _XML_TYPE { XML_ATTR, XML_ELEM, XML_VARIABLE_BEGIN = '$' } XML_TYPE;

/* XML structure */
typedef struct _OS_XML {
    unsigned int cur;           /* Current position (and last after reading) */
    int fol;                    /* Current position for the xml_access */
    XML_TYPE *tp;               /* Item type */
    unsigned int *rl;           /* Relation in the XML */
    int *ck;                    /* If the item was closed or not */
    unsigned int *ln;           /* Current xml file line */
    unsigned int err_line;      /* Line number of the possible error */
    char **ct;                  /* Content is stored */
    char **el;                  /* The element/attribute name is stored */
    char err[XML_ERR_LENGTH];   /* Error messages are stored in here */
    unsigned int line;          /* Current line */
    char stash[XML_STASH_LEN];  /* Ungot characters stash */
    int stash_i;                /* Stash index */
    FILE *fp;                   /* File descriptor */
    char *string;               /* XML string */
} OS_XML;

typedef xml_node **XML_NODE;

/* Start the XML structure reading a file */
int OS_ReadXML(const char *file, OS_XML *lxml) __attribute__((nonnull));

/* Start the XML structure reading a string */
int OS_ReadXMLString(const char *string, OS_XML *_lxml) __attribute__((nonnull));

/* Parse the XML */
int ParseXML(OS_XML *_lxml) __attribute__((nonnull));

/* Clear the XML structure memory */
void OS_ClearXML(OS_XML *_lxml) __attribute__((nonnull));

/* Clear a node */
void OS_ClearNode(xml_node **node);


/* Functions to read the XML */

/* Return 1 if element_name is a root element */
unsigned int OS_RootElementExist(const OS_XML *_lxml, const char *element_name) __attribute__((nonnull));

/* Return 1 if the element_name exists */
unsigned int OS_ElementExist(const OS_XML *_lxml, const char **element_name) __attribute__((nonnull));

/* Return the elements "children" of the element_name */
char **OS_GetElements(const OS_XML *_lxml, const char **element_name) __attribute__((nonnull(1)));

/* Return the elements "children" of the element_name */
xml_node **OS_GetElementsbyNode(const OS_XML *_lxml, const xml_node *node) __attribute__((nonnull(1)));

/* Return the attributes of the element name */
char **OS_GetAttributes(const OS_XML *_lxml, const char **element_name) __attribute__((nonnull(1)));

/* Return one value from element_name */
char *OS_GetOneContentforElement(OS_XML *_lxml, const char **element_name) __attribute__((nonnull));

/* Return an array with the content of all entries of element_name */
char **OS_GetElementContent(OS_XML *_lxml, const char **element_name) __attribute__((nonnull));

/* Return an array with the contents of an element_nane */
char **OS_GetContents(OS_XML *_lxml, const char **element_name) __attribute__((nonnull(1)));

/* Return the value of a specific attribute of the element_name */
char *OS_GetAttributeContent(OS_XML *_lxml, const char **element_name,
                             const char *attribute_name) __attribute__((nonnull(1, 2)));

/* Apply the variables to the xml */
int OS_ApplyVariables(OS_XML *_lxml) __attribute__((nonnull));

/* Error from writer */
#define XMLW_ERROR              006
#define XMLW_NOIN               007
#define XMLW_NOOUT              010

/* Write an XML file, based on the input and values to change */
int OS_WriteXML(const char *infile, const char *outfile, const char **nodes,
                const char *oldval, const char *newval) __attribute__((nonnull(1, 2, 3, 5)));

#endif /* __OS_XML_H */
