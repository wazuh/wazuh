/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml Library */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "os_xml.h"
#include "os_xml_internal.h"
#include "file_op.h"

/* Prototypes */
static int _oscomment(OS_XML *_lxml, int delim) __attribute__((nonnull));
static int _writecontent(const char *str, __attribute__((unused)) size_t size, unsigned int parent, OS_XML *_lxml) __attribute__((nonnull));
static int _writememory(const char *str, XML_TYPE type, size_t size,
                        unsigned int parent, OS_XML *_lxml) __attribute__((nonnull));
static int _xml_fgetc(FILE *fp, OS_XML *_lxml) __attribute__((nonnull));
int _xml_sgetc(OS_XML *_lxml)  __attribute__((nonnull));
static int _getattributes(unsigned int parent, OS_XML *_lxml, bool flag_truncate, const int delim) __attribute__((nonnull));
static void xml_error(OS_XML *_lxml, const char *msg, ...) __attribute__((format(printf, 2, 3), nonnull));

/**
 * @brief Recursive method to read XML elements.
 *
 * @param parent Current depth.
 * @param _lxml XML structure.
 * @param recursion_level Max recursion level allowed.
 * @param flag_truncate If TRUE, truncates the content of a tag when it's bigger than XML_MAXSIZE. Fails if set to FALSE.
 * @return int Returns 0, -1 or -2.
 */
static int _ReadElem(unsigned int parent, OS_XML *_lxml, unsigned int recursion_level, bool flag_truncate) __attribute__((nonnull));

/* Local fgetc */
static int _xml_fgetc(FILE *fp, OS_XML *_lxml)
{
    int c;

    // If there is any character in the stash, get it
    c = (_lxml->stash_i > 0) ? _lxml->stash[--_lxml->stash_i] : fgetc(fp);

    if (c == '\n') { /* add newline */
        _lxml->line++;
    }

    return (c);
}

int _xml_sgetc(OS_XML *_lxml){
    int c;

    if (_lxml->stash_i > 0) {
        c = _lxml->stash[--_lxml->stash_i];
    }
    else if (_lxml->string) {
        c = *(_lxml->string++);
    }
    else {
        c = -1;
    }

    if (c == '\n') { /* add newline */
        _lxml->line++;
    }

    return c;
}

static int _xml_ungetc(int c, OS_XML *_lxml)
{
    // If stash is full, give up
    if (_lxml->stash_i >= XML_STASH_LEN) {
        return -1;
    }

    _lxml->stash[_lxml->stash_i++] = c;

    if (c == '\n') { /* substract newline */
        _lxml->line--;
    }

    return 0;
}

static void xml_error(OS_XML *_lxml, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

    memset(_lxml->err, '\0', XML_ERR_LENGTH);
    vsnprintf(_lxml->err, XML_ERR_LENGTH - 1, msg, args);
    va_end(args);
    _lxml->err_line = _lxml->line;
}

/* Clear memory */
void OS_ClearXML(OS_XML *_lxml)
{
    unsigned int i;
    for (i = 0; i < _lxml->cur; i++) {
        free(_lxml->el[i]);
        free(_lxml->ct[i]);
    }
    _lxml->cur = 0;
    _lxml->fol = 0;
    _lxml->err_line = 0;

    free(_lxml->el);
    _lxml->el = NULL;

    free(_lxml->ct);
    _lxml->ct = NULL;

    free(_lxml->rl);
    _lxml->rl = NULL;

    free(_lxml->tp);
    _lxml->tp = NULL;

    free(_lxml->ck);
    _lxml->ck = NULL;

    free(_lxml->ln);
    _lxml->ln = NULL;

    memset(_lxml->err, '\0', XML_ERR_LENGTH);
    _lxml->line = 0;
    _lxml->stash_i = 0;
}

int ParseXML(OS_XML *_lxml, bool flag_truncate) {
    int r;
    unsigned int i;
    char *str_base = _lxml->string;

    /* Zero the line */
    _lxml->line = 1;

    // Reset stash
    _lxml->stash_i = 0;

    if ((r = _ReadElem(0, _lxml, 0, flag_truncate)) < 0) { /* First position */
        if (r != LEOF) {

            if(_lxml->fp){
                fclose(_lxml->fp);
            } else if (str_base){
                free(str_base);
            }

            return (-1);
        }
    }

    for (i = 0; i < _lxml->cur; i++) {
        if (_lxml->ck[i] == 0) {
            xml_error(_lxml, "XMLERR: Element '%s' not closed.", _lxml->el[i]);

            if(_lxml->fp){
                fclose(_lxml->fp);
            } else if (str_base){
                free(str_base);
            }

            return (-1);
        }
    }

    if(_lxml->fp){
        fclose(_lxml->fp);
    } else if (str_base){
        free(str_base);
    }

    return (0);
}

int OS_ReadXMLString_Ex(const char *string, OS_XML *_lxml, bool flag_truncate){
    /* Initialize xml structure */
    memset(_lxml, 0, sizeof(OS_XML));

    _lxml->string = strdup(string);
    _lxml->fp = NULL;

    return ParseXML(_lxml, flag_truncate);
}

int OS_ReadXMLString(const char *string, OS_XML *_lxml){
    return OS_ReadXMLString_Ex(string, _lxml, false);
}

/* Read a XML file and generate the necessary structs */
int OS_ReadXML_Ex(const char *file, OS_XML *_lxml, bool flag_truncate) {
    FILE *fp;

    /* Initialize xml structure */
    memset(_lxml, 0, sizeof(OS_XML));

    fp = wfopen(file, "r");
    if (!fp) {
        xml_error(_lxml, "XMLERR: File '%s' not found.", file);
        return (-2);
    }
    w_file_cloexec(fp);
    _lxml->fp = fp;
    _lxml->string = NULL;

    return ParseXML(_lxml, flag_truncate);
}

int OS_ReadXML(const char *file, OS_XML *_lxml) {
    return OS_ReadXML_Ex(file, _lxml, false);
}

static int _oscomment(OS_XML *_lxml, int delim)
{
    int c;
    if ((c = xml_getc_fun(_lxml->fp, _lxml)) == _R_COM) {
        while ((c = xml_getc_fun(_lxml->fp, _lxml)) != delim) {
            if (c == _R_COM) {
                if ((c = xml_getc_fun(_lxml->fp, _lxml)) == _R_CONFE) {
                    return (1);
                }
                _xml_ungetc(c, _lxml);
            } else if (c == '-') {  /* W3C way of finishing comments */
                if ((c = xml_getc_fun(_lxml->fp, _lxml)) == '-') {
                    if ((c = xml_getc_fun(_lxml->fp, _lxml)) == _R_CONFE) {
                        return (1);
                    }
                    _xml_ungetc(c, _lxml);
                }
                _xml_ungetc(c, _lxml);
            } else {
                continue;
            }
        }
        return (-1);
    } else {
        _xml_ungetc(c, _lxml);
    }
    return (0);
}

static int _ReadElem(unsigned int parent, OS_XML *_lxml, unsigned int recursion_level, bool flag_truncate) {
    int c=0;
    unsigned int count = 0;
    unsigned int _currentlycont = 0;
    short int location = -1;
    int cmp = 0;
    int retval = -1;
    bool ignore_content = false;

    int prevv = 1;
    char *elem = NULL;
    char *cont = NULL;
    char *closedelim = NULL;

    if (++recursion_level > 1024) {
        // 1024 levels should be enough for configuration and eventchannel events
        xml_error(_lxml, "XMLERR: Max recursion level reached");
        return -1;
    }

    elem = calloc(XML_MAXSIZE + 1, sizeof(char));
    cont = calloc(XML_MAXSIZE + 1, sizeof(char));
    closedelim = calloc(XML_MAXSIZE + 1, sizeof(char));

    if (elem == NULL || cont == NULL || closedelim == NULL) {
        goto end;
    }

    if (_lxml->fp){
        cmp = EOF;
        _lxml->string = NULL;
    } else if (_lxml->string){
        cmp = '\0';
    }

    while ((c = xml_getc_fun(_lxml->fp, _lxml)) != cmp) {
        if (c == '\\') {
            prevv *= -1;
        } else if (c != _R_CONFS && prevv == -1){
            prevv = 1;
        }

        /* Max size */
        if (count >= XML_MAXSIZE) {
            if (flag_truncate && 1 == location) {
                ignore_content = true;
            } else {
                xml_error(_lxml, "XMLERR: String overflow.");
                goto end;
            }
        }

        /* Check for comments */
        if (c == _R_CONFS) {
            int r = 0;
            if ((r = _oscomment(_lxml, cmp)) < 0) {
                xml_error(_lxml, "XMLERR: Comment not closed.");
                goto end;
            } else if (r == 1) {
                continue;
            }
        }

        /* Real checking */
        if ((location == -1) && (prevv == 1)) {
            if (c == _R_CONFS) {
                if ((c = xml_getc_fun(_lxml->fp, _lxml)) == '/') {
                    xml_error(_lxml, "XMLERR: Element not opened.");
                    goto end;
                } else {
                    _xml_ungetc(c, _lxml);
                }
                location = 0;
            } else {
                continue;
            }
        }

        else if ((location == 0) && ((c == _R_CONFE) || isspace(c))) {
            int _ge = 0;
            int _ga = 0;
            elem[count] = '\0';

            /* Remove the / at the end of the element name */
            if (count > 0 && elem[count - 1] == '/') {
                _ge = '/';
                elem[count - 1] = '\0';
            }

            if (_writememory(elem, XML_ELEM, count + 1, parent, _lxml) < 0) {
                goto end;
            }
            _currentlycont = _lxml->cur - 1;
            if (isspace(c)) {
                if ((_ga = _getattributes(parent, _lxml, flag_truncate, cmp)) < 0) {
                    goto end;
                }
            }

            /* If the element is closed already (finished in />) */
            if ((_ge == '/') || (_ga == '/')) {
                if (_writecontent("\0", 2, _currentlycont, _lxml) < 0) {
                    goto end;
                }
                _lxml->ck[_currentlycont] = 1;
                _currentlycont = 0;
                count = 0;
                location = -1;

                memset(elem, '\0', XML_MAXSIZE);
                memset(closedelim, '\0', XML_MAXSIZE);
                memset(cont, '\0', XML_MAXSIZE);

                if (parent > 0) {
                    retval = 0;
                    goto end;
                }
            } else {
                count = 0;
                location = 1;
            }
        }

        else if ((location == 2) && (c == _R_CONFE)) {
            closedelim[count] = '\0';
            if (strcmp(closedelim, elem) != 0) {
                xml_error(_lxml, "XMLERR: Element '%s' not closed.", elem);
                goto end;
            }
            if (_writecontent(cont, strlen(cont) + 1, _currentlycont, _lxml) < 0) {
                goto end;
            }
            _lxml->ck[_currentlycont] = 1;
            memset(elem, '\0', XML_MAXSIZE);
            memset(closedelim, '\0', XML_MAXSIZE);
            memset(cont, '\0', XML_MAXSIZE);
            _currentlycont = 0;
            count = 0;
            location = -1;
            if (parent > 0) {
                retval = 0;
                goto end;
            }
        } else if ((location == 1) && (c == _R_CONFS) && (prevv == 1)) {
            if ((c = xml_getc_fun(_lxml->fp, _lxml)) == '/') {
                cont[count] = '\0';
                count = 0;
                location = 2;
                ignore_content = false;
            } else {
                _xml_ungetc(c, _lxml);
                _xml_ungetc(_R_CONFS, _lxml);

                if (_ReadElem(parent + 1, _lxml, recursion_level, flag_truncate) < 0) {
                    goto end;
                }
                count = 0;
            }
        } else {
            if (location == 0) {
                elem[count++] = (char) c;
            } else if (location == 1 && !ignore_content) {
                cont[count++] = (char) c;
            } else if (location == 2) {
                closedelim[count++] = (char) c;
            }

            if (_R_CONFS == c) {
                prevv = 1;
            }
        }
    }
    if (location == -1) {
        retval = LEOF;
    }

    xml_error(_lxml, "XMLERR: End of file and some elements were not closed.");

end:
    if (elem) {
        free(elem);
    }

    if (cont) {
        free(cont);
    }

    if (closedelim) {
        free(closedelim);
    }

    return retval;
}

static int _writememory(const char *str, XML_TYPE type, size_t size,
                        unsigned int parent, OS_XML *_lxml)
{
    char **tmp;
    int *tmp2;
    unsigned int *tmp3;
    XML_TYPE *tmp4;

    /* Allocate for the element */
    tmp = (char **)realloc(_lxml->el, (_lxml->cur + 1) * sizeof(char *));
    if (tmp == NULL) {
        goto fail;
    }
    _lxml->el = tmp;
    _lxml->el[_lxml->cur] = (char *)calloc(size, sizeof(char));
    if (_lxml->el[_lxml->cur] == NULL) {
        goto fail;
    }
    strncpy(_lxml->el[_lxml->cur], str, size - 1);

    /* Allocate for the content */
    tmp = (char **)realloc(_lxml->ct, (_lxml->cur + 1) * sizeof(char *));
    if (tmp == NULL) {
        goto fail;
    }
    _lxml->ct = tmp;
    _lxml->ct[_lxml->cur] = NULL;

    /* Allocate for the type */
    tmp4 = (XML_TYPE *) realloc(_lxml->tp, (_lxml->cur + 1) * sizeof(XML_TYPE));
    if (tmp4 == NULL) {
        goto fail;
    }
    _lxml->tp = tmp4;
    _lxml->tp[_lxml->cur] = type;

    /* Allocate for the relation */
    tmp3 = (unsigned int *) realloc(_lxml->rl, (_lxml->cur + 1) * sizeof(unsigned int));
    if (tmp3 == NULL) {
        goto fail;
    }
    _lxml->rl = tmp3;
    _lxml->rl[_lxml->cur] = parent;

    /* Allocate for the "check" */
    tmp2 = (int *) realloc(_lxml->ck, (_lxml->cur + 1) * sizeof(int));
    if (tmp2 == NULL) {
        goto fail;
    }
    _lxml->ck = tmp2;
    _lxml->ck[_lxml->cur] = 0;

    /* Allocate for the line */
    tmp3 = (unsigned int *) realloc(_lxml->ln, (_lxml->cur + 1) * sizeof(unsigned int));
    if (tmp3 == NULL) {
        goto fail;
    }
    _lxml->ln = tmp3;
    _lxml->ln[_lxml->cur] = _lxml->line;

    /* Attributes does not need to be closed */
    if (type == XML_ATTR) {
        _lxml->ck[_lxml->cur] = 1;
    }

    /* Check if it is a variable */
    if (strcasecmp(XML_VAR, str) == 0) {
        _lxml->tp[_lxml->cur] = XML_VARIABLE_BEGIN;
    }

    _lxml->cur++;
    return (0);

fail:
    snprintf(_lxml->err, XML_ERR_LENGTH, "XMLERR: Memory error.");
    return (-1);
}

static int _writecontent(const char *str, __attribute__((unused)) size_t size, unsigned int parent, OS_XML *_lxml)
{
    _lxml->ct[parent] = strdup(str);

    if ( _lxml->ct[parent] == NULL) {
        snprintf(_lxml->err, XML_ERR_LENGTH, "XMLERR: Memory error.");
        return (-1);
    }

    return (0);
}

/* Read the attributes of an element */
static int _getattributes(unsigned int parent, OS_XML *_lxml, bool flag_truncate, const int delim)
{
    int location = 0;
    unsigned int count = 0;
    int c;
    int c_to_match = 0;

    char attr[XML_MAXSIZE + 1];
    char value[XML_MAXSIZE + 1];

    memset(attr, '\0', XML_MAXSIZE + 1);
    memset(value, '\0', XML_MAXSIZE + 1);

    while ((c = xml_getc_fun(_lxml->fp, _lxml)) != delim) {
        if (count >= XML_MAXSIZE) {
            if (flag_truncate && 1 == location) {
                value[count - 1] = '\0';
                return (0);
            }
            attr[count - 1] = '\0';
            xml_error(_lxml,
                      "XMLERR: Overflow attempt at attribute '%.20s'.", attr);
            return (-1);
        }

        else if ((c == _R_CONFE) || ((location == 0) && (c == '/'))) {
            if (location == 1) {
                xml_error(_lxml, "XMLERR: Attribute '%s' not closed.",
                          attr);
                return (-1);
            } else if ((location == 0) && (count > 0)) {
                xml_error(_lxml, "XMLERR: Attribute '%s' has no value.",
                          attr);
                return (-1);
            } else if (c == '/') {
                return (c);
            } else {
                return (0);
            }
        } else if ((location == 0) && (c == '=')) {
            attr[count] = '\0';

            /* Check for existing attribute with same name */
            unsigned int i = _lxml->cur - 1;
            /* Search attributes backwards in same parent */
            while (_lxml->rl[i] == parent && _lxml->tp[i] == XML_ATTR) {
                if (strcmp(_lxml->el[i], attr) == 0) {
                    xml_error(_lxml, "XMLERR: Attribute '%s' already defined.", attr);
                    return (-1);
                }

                /* Continue with previous element */
                if (i == 0) {
                    break;
                }
                i--;
            }

            c = xml_getc_fun(_lxml->fp, _lxml);
            if ((c != '"') && (c != '\'')) {
                unsigned short int _err = 1;
                if (isspace(c)) {
                    while ((c = xml_getc_fun(_lxml->fp, _lxml)) != delim) {
                        if (isspace(c)) {
                            continue;
                        } else if ((c == '"') || (c == '\'')) {
                            _err = 0;
                            break;
                        } else {
                            break;
                        }
                    }
                }
                if (_err != 0) {
                    xml_error(_lxml,
                              "XMLERR: Attribute '%s' not followed by a \" or \'."
                              , attr);
                    return (-1);
                }
            }

            c_to_match = c;
            location = 1;
            count = 0;
        } else if ((location == 0) && (isspace(c))) {
            if (count == 0) {
                continue;
            } else {
                xml_error(_lxml, "XMLERR: Attribute '%s' has no value.", attr);
                return (-1);
            }
        } else if ((location == 1) && (c == c_to_match)) {
            value[count] = '\0';
            if (_writememory(attr, XML_ATTR, strlen(attr) + 1,
                             parent, _lxml) < 0) {
                return (-1);
            }
            if (_writecontent(value, count + 1, _lxml->cur - 1, _lxml) < 0) {
                return (-1);
            }
            c = xml_getc_fun(_lxml->fp, _lxml);
            if (isspace(c)) {
                return (_getattributes(parent, _lxml, flag_truncate, delim));
            } else if (c == _R_CONFE) {
                return (0);
            } else if (c == '/') {
                return (c);
            }

            xml_error(_lxml,
                      "XMLERR: Bad attribute closing for '%s'='%s'.",
                      attr, value);
            return (-1);
        } else if (location == 0) {
            attr[count++] = (char) c;
        } else if (location == 1) {
            value[count++] = (char) c;
        }
    }

    xml_error(_lxml, "XMLERR: End of file while reading an attribute.");
    return (-1);
}

const char * w_get_attr_val_by_name(xml_node * node, const char * name) {

    if (!node || !node->attributes || !name) {
        return NULL;
    }

    for (int i = 0; node->attributes[i]; i++) {
        if (strcmp(node->attributes[i], name) == 0) {
            return node->values[i];
        }
    }

    return NULL;
}
