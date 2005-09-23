/*      $OSSEC, os_xml.c, v0.3, 2005/02/11, Daniel B. Cid$      */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml Library.
 * Available at http://www.ossec.net/c/os_xml/
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#include "os_xml.h"

#define _R_CONFS 	'<'
#define _R_CONFE 	'>'
#define _R_EQUAL 	'='
#define _R_COM   	'!'
#define _R_VAR      '$'

#define OPEN            51
#define CLOSE           52

#define LEOF		-2

/* Internal functions */
int _oscomment(FILE *fp);
int _writecontent(char *str, unsigned int size, int parent, OS_XML *_lxml);
int _writememory(char *str, short int type, unsigned int size,
                                        int parent, OS_XML *_lxml);
int _checkmemory(char *str,OS_XML *_lxml);
int _ReadElem(FILE *fp, int position, int parent, OS_XML *_lxml);
int _getattributes(FILE *fp,int parent,OS_XML *_lxml);

/* Currently line */
int _line;

/* Local fgetc */
int _xml_fgetc(FILE *fp)
{
    int c;
    c = fgetc(fp);

    if(c == '\n') /* add new line */
        _line++;
    
    return(c);    
}

#define FGETC(fp) _xml_fgetc(fp)

void xml_error(OS_XML *_lxml,const char *msg,...)
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
    fprintf(stderr,"%d/%d/%d %d:%d:%d (LINE: %d)",p->tm_year+1900,p->tm_mon,
            p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec,_line);
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n\n");
#endif
    
    memset(_lxml->err,'\0', 128);
    vsnprintf(_lxml->err,127,msg,args);
    va_end(args);
}



/* OS_ClearXML v0.1
 * Clear the memory used by the XML
 */
void OS_ClearXML(OS_XML *_lxml)
{
    int i;
    for(i=0;i<_lxml->cur;i++)
    {
        if(_lxml->el[i])
            free(_lxml->el[i]);
        if(_lxml->ct[i])
            free(_lxml->ct[i]);
    }
    _lxml->cur = 0;
    free(_lxml->el);
    free(_lxml->ct);
    free(_lxml->rl);
    free(_lxml->tp);
    free(_lxml->ck);
    free(_lxml->ln);
    return;	
}


/* OS_ReadXML v0.1
 * Read a XML file and generate the necessary structs.
 */
int OS_ReadXML(char *file, OS_XML *_lxml)
{
    int r,i;
    FILE *fp;

    fp = fopen(file,"r");
    if(!fp)
    {
        xml_error(_lxml, "XMLERR: File \"%s\" not found.",file);
        return(-1);
    }

    _lxml->cur=0;
    _lxml->fol=0;
    _lxml->el=NULL;
    _lxml->ct=NULL;
    _lxml->tp=NULL;
    _lxml->rl=NULL;
    _lxml->ck=NULL;
    _lxml->ln=NULL;

    memset(_lxml->err,'\0',128);

    /* Zeroring the line */
    _line = 0;

    if((r=_ReadElem(fp,0,0,_lxml)) < 0) /* First position */
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
            xml_error(_lxml,"XMLERR: Element \"%s\" not closed\n",_lxml->el[i]);
            fclose(fp);
            return(-1);
        }
    }
    fclose(fp);
    return(0);
}


int _oscomment(FILE *fp)
{
    int c;
    if((c = fgetc(fp)) == _R_COM)
    {
        while((c=FGETC(fp)) != EOF)
        {
            if(c == _R_COM)
            {
                if((c=fgetc(fp)) == _R_CONFE)
                    return(1);
                ungetc(c,fp);
            }
            else if(c == '-')       /* W3C way of finish comments */
            {
                if((c = FGETC(fp)) == '-')
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

int _ReadElem(FILE *fp, int position, int parent, OS_XML *_lxml)
{
    int c;
    unsigned int count=0;
    unsigned int _currentlycont=0;
    short int location=-1;

    char elem[XML_MAXSIZE];
    char cont[XML_MAXSIZE];
    char closedelem[XML_MAXSIZE];

    
    memset(elem,'\0',XML_MAXSIZE);
    memset(cont,'\0',XML_MAXSIZE);
    memset(closedelem,'\0',XML_MAXSIZE);

    while((c=FGETC(fp)) != EOF)
    {
        if(count >= XML_MAXSIZE)
        {
            xml_error(_lxml,"XML ERR: String overflow. Exiting.");
            return(-1);
        }
        else if(location == -1)
        {
            if(c == _R_CONFS)
            {
                int r=0;
                if((r = _oscomment(fp)) < 0)
                {
                    xml_error(_lxml,"XML ERR: Comment not closed. Bad XML.");
                    return(0);
                }
                else if(r == 1)
                    continue;
                else if((c=fgetc(fp)) == '/')
                {
                    xml_error(_lxml,"XML ERR: Bad formed XML. Not opened "
                                    "element");
                    return(-1);
                }
                else
                    ungetc(c,fp);
                location=0;
            }
            else
                continue;
        }
        
        else if((location == 0) &&((c == _R_CONFE) || (c == ' ')))
        {
            elem[count]='\0';
            _writememory(elem, XML_ELEM, count+1, parent, _lxml);
            _currentlycont=_lxml->cur-1;
            if(c == ' ')
            {
                if(_getattributes(fp,parent,_lxml) < 0)
                    return(-1);
            }
            count=0;
            location=1;	
        }
        
        else if((location == 2) &&(c == _R_CONFE))
        {
            closedelem[count]='\0';
            if(strcmp(closedelem,elem) != 0)
            {
                xml_error(_lxml,"XML ERR: Element not closed: %s",elem);
                return(-1);
            }
            _writecontent(cont,strlen(cont)+1,_currentlycont,_lxml);
            _lxml->ck[_currentlycont]=1;	
            memset(elem,'\0',XML_MAXSIZE);
            memset(closedelem,'\0',XML_MAXSIZE);
            memset(cont,'\0',XML_MAXSIZE);
            _currentlycont=0;
            count=0;	
            location=-1;
            if(parent > 0)
                return(0);
        }
        else if((location == 1) &&(c == _R_CONFS))
        {
            if((c=fgetc(fp)) == '/')
            {
                cont[count]='\0';
                count=0;
                location=2;
            }	
            else
            {
                ungetc(c,fp);
                ungetc(_R_CONFS,fp);

                if(_ReadElem(fp,position+1,parent+1,_lxml)< 0)
                {
                    return(-1);
                }
                count=0;
            }
        }
        else
        {
            if(location == 0)
                elem[count++]=c;
            else if(location == 1)
                cont[count++]=c;
            else if(location == 2)
                closedelem[count++]=c;
        }
    }
    if(location == -1)
        return(LEOF);

    xml_error(_lxml,"XML ERR: End of file and some elements were not closed");
    return(-1);
}				

int _writememory(char *str, short int type, unsigned int size,
                                        int parent, OS_XML *_lxml)
{
    /* Allocating for the element */
    _lxml->el = (char **)realloc(_lxml->el,(_lxml->cur+1)*sizeof(char *));
    _lxml->el[_lxml->cur]=(char *)calloc(size,sizeof(char));
    strncpy(_lxml->el[_lxml->cur],str,size-1);

    /* Allocating for the content */	
    _lxml->ct = (char **)realloc(_lxml->ct,(_lxml->cur+1)*sizeof(char *));

    /* Allocating for the type */
    _lxml->tp = realloc(_lxml->tp,(_lxml->cur+1)*sizeof(int));
    _lxml->tp[_lxml->cur]=type;	

    /* Allocating for the relation */
    _lxml->rl = realloc(_lxml->rl,(_lxml->cur+1)*sizeof(int));
    _lxml->rl[_lxml->cur]=parent;

    /* Allocating for the "check" */
    _lxml->ck = realloc(_lxml->ck,(_lxml->cur+1)*sizeof(int));
    _lxml->ck[_lxml->cur]=0;

    /* Allocating for the line */
    _lxml->ln = realloc(_lxml->ln,(_lxml->cur+1)*sizeof(int));
    _lxml->ln[_lxml->cur]=_line;
    
    /* Attributes does not need to be closed */
    if(type == XML_ATTR)
        _lxml->ck[_lxml->cur]=1;

    /* Checking if it is a variable */
    if(strcasecmp(XML_VAR,str) == 0)
        _lxml->tp[_lxml->cur]=XML_VARIABLE_BEGIN;

    _lxml->cur++;
    return(0);
}

int _writecontent(char *str, unsigned int size, int parent, OS_XML *_lxml)
{
    _lxml->ct[parent]=(char *)calloc(size,sizeof(char));
    strncpy(_lxml->ct[parent],str,size-1);

    return(0);
}


int _checkmemory(char *str,OS_XML *_lxml)
{
    int i;
    for(i=0;i<_lxml->cur;i++)
    {
        if(_lxml->ck[i] == 0)
        {
            if(strcmp(str,_lxml->el[i]) == 0)
            {
                _lxml->ck[i]=1;
                return(0);
            }
            else
                continue;
        }
    }
    return(-1);
}

/* getattributes (Internal function): v0.1: 2005/03/03
 * Read the attributes of an element
 */
int _getattributes(FILE *fp,int parent,OS_XML *_lxml)
{
    int location=0;
    int count=0;
    char c;
    char attr[XML_MAXSIZE+1];
    char value[XML_MAXSIZE+1];

    memset(attr,'\0',XML_MAXSIZE+1);
    memset(value,'\0',XML_MAXSIZE+1);

    while((c=FGETC(fp)) != EOF)
    {
        if(count >= XML_MAXSIZE)
        {
            attr[count-1]='\0';
            xml_error(_lxml, 
                    "XMLERR: Overflow attempt at attribute \"%s\".",attr);
            return(-1);
        }

        else if(c == _R_CONFE)
        {
            if((location == 1)||((location == 0)&&(count > 0)))
            {
                xml_error(_lxml, "XMLERR: Attribute \"%s\" not closed."
                        ,attr);
                return(-1);
            }
            else
                return(0);
        }	
        else if((location == 0)&&(c == '='))
        {
            attr[count]='\0';
            c=FGETC(fp);
            if((c != '"')&&(c != '\''))
            {
                unsigned short int _err=1;
                if(c == ' ')
                {
                    while((c=FGETC(fp))!= EOF)
                    {
                        if(c == ' ')
                            continue;
                        else if((c == '"')||(c == '\''))
                        {
                            _err=0;
                            break;
                        }
                        else
                            break;
                    }
                }
                if(_err != 0){
                    xml_error(_lxml,
                            "XMLERR: Attribute \"%s not\" followed by a \" or \'."
                            ,attr);
                    return(-1); }
            }
            location=1;
            count=0;
        }
        else if((location == 0)&&(c == ' '))
            continue;

        else if((location == 1)&&((c == '"')||(c == '\'')))
        {
            value[count]='\0';
            location=0;
            _writememory(attr, XML_ATTR, strlen(attr)+1, 
                    parent, _lxml);	
            _writecontent(value,count+1,_lxml->cur-1,_lxml);
            c=FGETC(fp);
            if(c == ' ')
                return(_getattributes(fp,parent,_lxml));
            else if(c == _R_CONFE)
                return(0);
            else
            {
                xml_error(_lxml,
                        "XMLERR: Bad attribute closing for: %s=%s\n",
                        attr,value);
                return(-1);
            }
            count=0;
        }
        else if(location == 0)
            attr[count++]=c;
        else if(location == 1)
            value[count++]=c;

    }
    xml_error(_lxml, "XMLERR: End of file while reading an attribute.");
    return(-1);
}

/* EOF */
