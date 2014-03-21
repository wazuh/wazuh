/* @(#) $Id: ./src/os_xml/os_xml_writer.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* os_xml Library.
 * Available at http://www.ossec.net/
 */

#include <stdio.h>
#include <string.h>

#include "os_xml.h"
#include "os_xml_internal.h"

/* Internal functions */
static int _oswcomment(FILE *fp_in, FILE *fp_out) __attribute__((nonnull));
static int _WReadElem(FILE *fp_in, FILE *fp_out, unsigned int position, unsigned int parent,
		const char **node, const char *value, unsigned int node_pos) __attribute__((nonnull));
static int _xml_wfgetc(FILE *fp_in, FILE *fp_out) __attribute__((nonnull));

/* Local fgetc */
static int _xml_wfgetc(FILE *fp_in, FILE *fp_out)
{
    int c;

    /* Putting on fp_out, whatever we read */
    c = fgetc(fp_in);
    if(c != EOF)
    {
        fputc(c, fp_out);
    }

    return(c);
}

/* OS_WriteXML
 * Write an XML file, based on the input and values to change.
 */
int OS_WriteXML(const char *infile, const char *outfile, const char **nodes,
		const char *oldval, const char *newval)
{
    int r = 0;
    FILE *fp_in;
    FILE *fp_out;


    /* Opening infile */
    fp_in = fopen(infile,"r");
    if(!fp_in)
    {
        return(XMLW_NOIN);
    }


    /* Opening out file */
    fp_out = fopen(outfile,"w");
    if(!fp_out)
    {
        fclose(fp_in);
        return(XMLW_NOOUT);
    }


    if((r = _WReadElem(fp_in, fp_out, 0, 0,
                       nodes, newval, 0)) < 0) /* First position */
    {
        fclose(fp_in);
        fclose(fp_out);
        return(XMLW_ERROR);
    }

    /* We didn't find an entry, add at the end. */
    if(!oldval && r == 0)
    {
        int s = 0;
        int rwidth = 0;

        fseek(fp_out, 0, SEEK_END);
        fprintf(fp_out, "\n");

        /* Printing each node. */
        while(nodes[s])
        {
            fprintf(fp_out, "%*c<%s>", rwidth, ' ', nodes[s]);
            s++;
            rwidth += 3;

            if(nodes[s])
                fprintf(fp_out, "\n");
        }

        /* Printing val. */
        s--;
        rwidth -=6;
        fprintf(fp_out, "%s</%s>\n", newval, nodes[s]);
        s--;


        /* Closing each node. */
        while(s >= 0)
        {
            fprintf(fp_out, "%*c</%s>\n", rwidth, ' ', nodes[s]);
            s--;
            rwidth -= 3;
        }
    }

    fclose(fp_in);
    fclose(fp_out);
    return(0);
}



/* Getting comments */
static int _oswcomment(FILE *fp_in, FILE *fp_out)
{
    int c;
    if((c = fgetc(fp_in)) == _R_COM)
    {
        fputc(c, fp_out);
        while((c = _xml_wfgetc(fp_in, fp_out)) != EOF)
        {
            if(c == _R_COM)
            {
                if((c=fgetc(fp_in)) == _R_CONFE)
                {
                    fputc(c, fp_out);
                    return(1);
                }
                ungetc(c,fp_in);
            }
            else if(c == '-')       /* W3C way of finish comments */
            {
                if((c = fgetc(fp_in)) == '-')
                {
                    fputc(c, fp_out);
                    if((c = fgetc(fp_in)) == _R_CONFE)
                    {
                        fputc(c, fp_out);
                        return(1);
                    }
                    ungetc(c,fp_in);
                }
                else
                {
                    ungetc(c,fp_in);
                }
            }
            else
            {
                continue;
            }
        }
        return(-1);
    }
    else
    {
        ungetc(c,fp_in);
    }

    return(0);
}



static int _WReadElem(FILE *fp_in, FILE *fp_out,
              unsigned int position, unsigned int parent, const char **nodes, const char *val, unsigned int node_pos)
{
    int c;
    int ret_code = 0;
    unsigned int count = 0;
    short int location = -1;

    char elem[XML_MAXSIZE +1];
    char cont[XML_MAXSIZE +1];
    char closedelem[XML_MAXSIZE +1];

    memset(elem,'\0',XML_MAXSIZE +1);
    memset(cont,'\0',XML_MAXSIZE +1);
    memset(closedelem,'\0',XML_MAXSIZE +1);


    while((c = _xml_wfgetc(fp_in, fp_out)) != EOF)
    {
        /* Max size */
        if(count >= XML_MAXSIZE)
        {
            return(-1);
        }

        /* Checking for comments */
        if(c == _R_CONFS)
        {
            int r = 0;
            if((r = _oswcomment(fp_in, fp_out)) < 0)
            {
                return(-1);
            }
            else if(r == 1)
            {
                continue;
            }
        }


        /* Real checking */
        if(location == -1)
        {
            /* Must be the opening element */
            if(c == _R_CONFS)
            {
                if((c = fgetc(fp_in)) == '/')
                {
                    return(-1);
                }
                else
                {
                    ungetc(c,fp_in);
                }
                location = 0;
            }
            else
            {
                continue;
            }
        }


        /* Looking for the closure */
        else if((location == 0) && ((c == _R_CONFE) || (c == ' ')))
        {
            int _ge = 0;
            elem[count] = '\0';


            /* Removing the / at the end of the element name */
            if(elem[count -1] == '/')
            {
                _ge = '/';
                elem[count -1] = '\0';
            }


            /* If we may have more attributes */
            if(c == ' ')
            {
                /* Writing the attributes */
                while((c = _xml_wfgetc(fp_in, fp_out)) != EOF)
                {
                    if(c == _R_CONFE)
                    {
                        break;
                    }
                }
            }


            /* If the element is closed already (finished in />) */
            if(_ge == '/')
            {
                count = 0;
                location = -1;

                memset(elem,'\0',XML_MAXSIZE);
                memset(closedelem,'\0',XML_MAXSIZE);
                memset(cont,'\0',XML_MAXSIZE);

                if(parent > 0)
                {
                    return(ret_code);
                }
            }
            /* Location == means we are getting the content */
            else
            {
                count = 0;
                location = 1;
            }


            /* Checking position of the node */
            if(node_pos > position)
            {
                node_pos = 0;
            }

            /* Checking if the element name matches */
            if(node_pos == position &&
               nodes[node_pos] && strcmp(elem, nodes[node_pos]) == 0)
            {
                node_pos++;

                /* Latest node, printint value */
                if(!nodes[node_pos])
                {
                    ret_code = 1;
                    fprintf(fp_out, "%s", val);

                    while((c = fgetc(fp_in)) != EOF)
                    {
                        if(c == _R_CONFS)
                        {
                            ungetc(c,fp_in);
                            break;
                        }
                    }
                }
            }
        }

        else if((location == 2) &&(c == _R_CONFE))
        {
            closedelem[count]='\0';
            if(strcmp(closedelem,elem) != 0)
            {
                return(-1);
            }

            memset(elem,'\0',XML_MAXSIZE);
            memset(closedelem,'\0',XML_MAXSIZE);
            memset(cont,'\0',XML_MAXSIZE);

            count = 0;
            location = -1;
            if(parent > 0)
            {
                return(ret_code);
            }
        }

        /* If we are reading the element */
        else if((location == 1) &&(c == _R_CONFS))
        {
            if((c=fgetc(fp_in)) == '/')
            {
                fputc(c, fp_out);

                cont[count] = '\0';
                count = 0;
                location = 2;
            }
            else
            {
                int wret_code;
                ungetc(c,fp_in);
                ungetc(_R_CONFS,fp_in);
                fseek(fp_out, -1, SEEK_CUR);

                if((wret_code = _WReadElem(fp_in, fp_out, position+1, parent+1,
                             nodes, val, node_pos))< 0)
                {
                    return(-1);
                }

                /* Setting final return code. */
                if(wret_code == 1)
                {
                    ret_code = 1;
                }

                count = 0;
            }
        }
        else
        {
            if(location == 0)
            {
                elem[count++] = (char) c;
            }
            else if(location == 1)
            {
                cont[count++] = (char) c;
            }
            else if(location == 2)
            {
                closedelem[count++] = (char) c;
            }
        }
    }

    if(location == -1)
    {
        return(ret_code);
    }


    return(-1);
}




/* EOF */
