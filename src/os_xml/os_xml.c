/*      $OSSEC, os_xml.c, v0.3, 2005/02/11, Daniel B. Cid$      */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml Library.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "os_xml.h"
#include "os_xml_internal.h"


/* Internal functions */
static int _oscomment(FILE *fp) __attribute__((nonnull));
static int _writecontent(const char *str, size_t size, unsigned int parent, OS_XML *_lxml) __attribute__((nonnull));
static int _writememory(const char *str, XML_TYPE type, size_t size,
                                        unsigned int parent, OS_XML *_lxml) __attribute__((nonnull));
static int _xml_fgetc(FILE *fp) __attribute__((nonnull));
static int _ReadElem(FILE *fp, unsigned int parent, OS_XML *_lxml) __attribute__((nonnull));
static int _getattributes(FILE *fp, unsigned int parent,OS_XML *_lxml) __attribute__((nonnull));
static void xml_error(OS_XML *_lxml, const char *msg,...) __attribute__((format(printf, 2, 3), nonnull));

/* Currently line */
static unsigned int _line;

/* Local fgetc */
static int _xml_fgetc(FILE *fp)
{
    int c;
    c = fgetc(fp);

    if(c == '\n') /* add new line */
        _line++;

    return(c);
}

static void xml_error(OS_XML *_lxml, const char *msg,...)
{
#ifdef DEBUG
    time_t tm;
    struct tm *p;
#endif

    va_list args;
    va_start(args,msg);

#ifdef DEBUG
    tm = time(NULL);
    p = localtime(&tm);
    fprintf(stderr,"%d/%d/%d %d:%d:%d (LINE: %u)",p->tm_year+1900,p->tm_mon,
            p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec,_line);
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n\n");
#endif

    memset(_lxml->err,'\0', XML_ERR_LENGTH);
    vsnprintf(_lxml->err,XML_ERR_LENGTH-1,msg,args);
    va_end(args);
    _lxml->err_line = _line;
}



/* OS_ClearXML v0.1
 * Clear the memory used by the XML
 */
void OS_ClearXML(OS_XML *_lxml)
{
    unsigned int i;
    for(i=0;i<_lxml->cur;i++)
    {
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

    memset(_lxml->err,'\0', XML_ERR_LENGTH);
}


/* OS_ReadXML v0.1
 * Read a XML file and generate the necessary structs.
 */
int OS_ReadXML(const char *file, OS_XML *_lxml)
{
    int r;
    unsigned int i;
    FILE *fp;

    /* init xml strcuture */
    _lxml->cur = 0;
	_lxml->fol = 0;
	_lxml->el = NULL;
	_lxml->ct = NULL;
	_lxml->tp = NULL;
	_lxml->rl = NULL;
	_lxml->ck = NULL;
	_lxml->ln = NULL;

	_lxml->err_line = 0;
	memset(_lxml->err,'\0',XML_ERR_LENGTH);

    fp = fopen(file,"r");
    if(!fp)
    {
        xml_error(_lxml, "XMLERR: File '%s' not found.",file);
        return(-2);
    }

    /* Zeroing the line */
    _line = 1;

    if((r = _ReadElem(fp,0,_lxml)) < 0) /* First position */
    {
        if(r != LEOF)
        {
            fclose(fp);
            return(-1);
        }
    }

    for(i=0;i<_lxml->cur;i++)
    {
        if(_lxml->ck[i] == 0)
        {
            xml_error(_lxml,"XMLERR: Element '%s' not closed.", _lxml->el[i]);
            fclose(fp);
            return(-1);
        }
    }

    fclose(fp);
    return(0);
}


static int _oscomment(FILE *fp)
{
    int c;
    if((c = fgetc(fp)) == _R_COM)
    {
        while((c=_xml_fgetc(fp)) != EOF)
        {
            if(c == _R_COM)
            {
                if((c=fgetc(fp)) == _R_CONFE)
                    return(1);
                ungetc(c,fp);
            }
            else if(c == '-')       /* W3C way of finish comments */
            {
                if((c = _xml_fgetc(fp)) == '-')
                {
                    if((c = fgetc(fp)) == _R_CONFE)
                        return(1);
                    ungetc(c,fp);
                }
                ungetc(c,fp);
            }
            else
                continue;
        }
        return(-1);
    }
    else
        ungetc(c,fp);
    return(0);
}


static int _ReadElem(FILE *fp, unsigned int parent, OS_XML *_lxml)
{
    int c;
    unsigned int count = 0;
    unsigned int _currentlycont = 0;
    short int location = -1;

    int prevv = 0;
    char elem[XML_MAXSIZE +1];
    char cont[XML_MAXSIZE +1];
    char closedelem[XML_MAXSIZE +1];



    memset(elem,'\0',XML_MAXSIZE +1);
    memset(cont,'\0',XML_MAXSIZE +1);
    memset(closedelem,'\0',XML_MAXSIZE +1);

    while((c=_xml_fgetc(fp)) != EOF)
    {
        if(c == '\\')
            prevv = c;
        else if(prevv == '\\')
        {
            if(c != _R_CONFS)
                prevv = 0;
        }


        /* Max size */
        if(count >= XML_MAXSIZE)
        {
            xml_error(_lxml,"XMLERR: String overflow.");
            return(-1);
        }


        /* Checking for comments */
        if(c == _R_CONFS)
        {
            int r = 0;
            if((r = _oscomment(fp)) < 0)
            {
                xml_error(_lxml,"XMLERR: Comment not closed.");
                return(-1);
            }
            else if(r == 1)
                continue;
        }

        /* real checking */
        if((location == -1) && (prevv == 0))
        {
            if(c == _R_CONFS)
            {
                if((c=fgetc(fp)) == '/')
                {
                    xml_error(_lxml,"XMLERR: Element not opened.");
                    return(-1);
                }
                else
                    ungetc(c,fp);
                location = 0;
            }
            else
                continue;
        }

        else if((location == 0) && ((c == _R_CONFE) || isspace(c)))
        {
            int _ge = 0;
            int _ga = 0;
            elem[count]='\0';

            /* Removing the / at the end of the element name */
            if(elem[count -1] == '/')
            {
                _ge = '/';
                elem[count -1] = '\0';
            }

            if(_writememory(elem, XML_ELEM, count+1, parent, _lxml) < 0)
            {
                return(-1);
            }
            _currentlycont=_lxml->cur-1;
            if(isspace(c))
            {
                if((_ga = _getattributes(fp,parent,_lxml)) < 0)
                    return(-1);
            }

            /* If the element is closed already (finished in />) */
            if((_ge == '/') || (_ga == '/'))
            {
                if(_writecontent("\0", 2, _currentlycont,_lxml) < 0)
                {
                    return(-1);
                }
                _lxml->ck[_currentlycont] = 1;
                _currentlycont = 0;
                count = 0;
                location = -1;

                memset(elem,'\0',XML_MAXSIZE);
                memset(closedelem,'\0',XML_MAXSIZE);
                memset(cont,'\0',XML_MAXSIZE);

                if(parent > 0)
                    return(0);
            }
            else
            {
                count = 0;
                location = 1;
            }
        }

        else if((location == 2) &&(c == _R_CONFE))
        {
            closedelem[count]='\0';
            if(strcmp(closedelem,elem) != 0)
            {
                xml_error(_lxml,"XMLERR: Element '%s' not closed.",elem);
                return(-1);
            }
            if(_writecontent(cont,strlen(cont)+1,_currentlycont,_lxml) < 0)
            {
                return(-1);
            }
            _lxml->ck[_currentlycont]=1;
            memset(elem,'\0',XML_MAXSIZE);
            memset(closedelem,'\0',XML_MAXSIZE);
            memset(cont,'\0',XML_MAXSIZE);
            _currentlycont = 0;
            count = 0;
            location = -1;
            if(parent > 0)
                return(0);
        }
        else if((location == 1) && (c == _R_CONFS) && (prevv == 0))
        {
            if((c=fgetc(fp)) == '/')
            {
                cont[count] = '\0';
                count = 0;
                location = 2;
            }
            else
            {
                ungetc(c,fp);
                ungetc(_R_CONFS,fp);

                if(_ReadElem(fp,parent+1,_lxml)< 0)
                {
                    return(-1);
                }
                count=0;
            }
        }
        else
        {
            if(location == 0)
                elem[count++] = (char) c;
            else if(location == 1)
                cont[count++] = (char) c;
            else if(location == 2)
                closedelem[count++] = (char) c;

            if((_R_CONFS == c) && (prevv != 0))
            {
                prevv = 0;
            }
        }
    }
    if(location == -1)
        return(LEOF);

    xml_error(_lxml,"XMLERR: End of file and some elements were not closed.");
    return(-1);
}

static int _writememory(const char *str, XML_TYPE type, size_t size,
                                        unsigned int parent, OS_XML *_lxml)
{
    char **tmp;
    int *tmp2;
    unsigned int *tmp3;
    XML_TYPE *tmp4;

    /* Allocating for the element */
    tmp = (char **)realloc(_lxml->el,(_lxml->cur+1)*sizeof(char *));
    if(tmp == NULL)
    {
        goto fail;
    }
    _lxml->el = tmp;
    _lxml->el[_lxml->cur]=(char *)calloc(size,sizeof(char));
    if(_lxml->el[_lxml->cur] == NULL)
    {
        goto fail;
    }
    strncpy(_lxml->el[_lxml->cur],str,size-1);

    /* Allocating for the content */
    tmp = (char **)realloc(_lxml->ct,(_lxml->cur+1)*sizeof(char *));
    if(tmp == NULL)
    {
        goto fail;
    }
    _lxml->ct = tmp;
    _lxml->ct[_lxml->cur] = NULL;

    /* Allocating for the type */
    tmp4 = (XML_TYPE *) realloc(_lxml->tp,(_lxml->cur+1)*sizeof(XML_TYPE));
    if(tmp4 == NULL)
    {
        goto fail;
    }
    _lxml->tp = tmp4;
    _lxml->tp[_lxml->cur] = type;

    /* Allocating for the relation */
    tmp3 = (unsigned int *) realloc(_lxml->rl,(_lxml->cur+1)*sizeof(unsigned int));
    if(tmp3 == NULL)
    {
        goto fail;
    }
    _lxml->rl = tmp3;
    _lxml->rl[_lxml->cur] = parent;

    /* Allocating for the "check" */
    tmp2 = (int *) realloc(_lxml->ck,(_lxml->cur+1)*sizeof(int));
    if(tmp2 == NULL)
    {
        goto fail;
    }
    _lxml->ck = tmp2;
    _lxml->ck[_lxml->cur] = 0;

    /* Allocating for the line */
    tmp3 = (unsigned int *) realloc(_lxml->ln,(_lxml->cur+1)*sizeof(unsigned int));
    if(tmp3 == NULL)
    {
        goto fail;
    }
    _lxml->ln = tmp3;
    _lxml->ln[_lxml->cur] = _line;

    /* Attributes does not need to be closed */
    if(type == XML_ATTR)
        _lxml->ck[_lxml->cur] = 1;

    /* Checking if it is a variable */
    if(strcasecmp(XML_VAR,str) == 0)
    {
        _lxml->tp[_lxml->cur] = XML_VARIABLE_BEGIN;
    }

    _lxml->cur++;
    return(0);

    fail:
    snprintf(_lxml->err, XML_ERR_LENGTH, "XMLERR: Memory error.");
    return(-1);
}

static int _writecontent(const char *str, size_t size, unsigned int parent, OS_XML *_lxml)
{
    _lxml->ct[parent]=(char *)calloc(size,sizeof(char));
    if( _lxml->ct[parent] == NULL)
    {
        snprintf(_lxml->err, XML_ERR_LENGTH, "XMLERR: Memory error.");
        return(-1);
    }
    strncpy(_lxml->ct[parent],str,size-1);

    return(0);
}


/* getattributes (Internal function): v0.1: 2005/03/03
 * Read the attributes of an element
 */
static int _getattributes(FILE *fp, unsigned int parent,OS_XML *_lxml)
{
    int location = 0;
    unsigned int count = 0;
    int c;
    int c_to_match = 0;

    char attr[XML_MAXSIZE+1];
    char value[XML_MAXSIZE+1];

    memset(attr,'\0',XML_MAXSIZE+1);
    memset(value,'\0',XML_MAXSIZE+1);

    while((c=_xml_fgetc(fp)) != EOF)
    {
        if(count >= XML_MAXSIZE)
        {
            attr[count-1] = '\0';
            xml_error(_lxml,
                    "XMLERR: Overflow attempt at attribute '%.20s'.",attr);
            return(-1);
        }

        else if((c == _R_CONFE) || ((location == 0) && (c == '/')))
        {
            if(location == 1)
            {
                xml_error(_lxml, "XMLERR: Attribute '%s' not closed.",
                                 attr);
                return(-1);
            }
            else if((location == 0)&&(count > 0))
            {
                xml_error(_lxml, "XMLERR: Attribute '%s' has no value.",
                                                 attr);
                                return(-1);
            }
            else if(c == '/')
                return(c);
            else
                return(0);
        }
        else if((location == 0)&&(c == '='))
        {
            attr[count]='\0';

            /* check for already existent attribute with same name */
            unsigned int i = _lxml->cur - 1;
            /* search attributes backwards in same parent */
            while(_lxml->rl[i] == parent && _lxml->tp[i] == XML_ATTR)
            {
                if(strcmp(_lxml->el[i], attr) == 0)
                {
                    xml_error(_lxml, "XMLERR: Attribute '%s' already defined.", attr);
                    return(-1);
                }

                /* continue with previous element */
                if(i==0)
                {
                    break;
                }
                i--;
            }

            c = _xml_fgetc(fp);
            if((c != '"')&&(c != '\''))
            {
                unsigned short int _err=1;
                if(isspace(c))
                {
                    while((c=_xml_fgetc(fp))!= EOF)
                    {
                        if(isspace(c))
                            continue;
                        else if((c == '"')||(c == '\''))
                        {
                            _err = 0;
                            break;
                        }
                        else
                            break;
                    }
                }
                if(_err != 0){
                    xml_error(_lxml,
                            "XMLERR: Attribute '%s' not followed by a \" or \'."
                            ,attr);
                    return(-1); }
            }

            c_to_match = c;
            location = 1;
            count = 0;
        }
        else if((location == 0)&&(isspace(c)))
        {
            if(count == 0)
            {
                continue;
            }
            else
            {
                xml_error(_lxml, "XMLERR: Attribute '%s' has no value.", attr);
                return(-1);
            }
        }
        else if((location == 1)&&(c == c_to_match))
        {
            value[count]='\0';

            /* dead code:
             * location = 0;
             * c_to_match = 0;
             */

            if(_writememory(attr, XML_ATTR, strlen(attr)+1,
                    parent, _lxml) < 0)
            {
                return(-1);
            }
            if(_writecontent(value,count+1,_lxml->cur-1,_lxml) < 0)
            {
                return(-1);
            }
            c = _xml_fgetc(fp);
            if(isspace(c))
                return(_getattributes(fp,parent,_lxml));
            else if(c == _R_CONFE)
                return(0);
            else if(c == '/')
            	return (c);

            xml_error(_lxml,
                "XMLERR: Bad attribute closing for '%s'='%s'.",
                attr,value);
            return(-1);
        }
        else if(location == 0)
            attr[count++] = (char) c;
        else if(location == 1)
            value[count++] = (char) c;

    }

    xml_error(_lxml, "XMLERR: End of file while reading an attribute.");
    return(-1);
}

/* EOF */
