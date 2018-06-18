/***************************************************************************
 *   Copyright (C) 2007 International Business Machines  Corp.             *
 *   All Rights Reserved.                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                         *
 * Authors:                                                                *
 *   Klaus Heinrich Kiwi <klausk@br.ibm.com>                               *
 ***************************************************************************/

#ifndef _ZOS_REMOTE_LDAP_H
#define _ZOS_REMOTE_LDAP_H

#include <lber.h>
#include <ldap.h>


/***************************************************************************
 *   LDAP Extended Op OID for ICTX Audit                                   *
 ***************************************************************************/
/* ICTX EIM component AUDIT Request OID */
#define ICTX_OIDAUDITREQUEST     "1.3.18.0.2.12.68"

/* The AUDIT Response OID */
#define ICTX_OIDAUDITRESPONSE    "1.3.18.0.2.12.69"

/* This implementation version
   Request and response must match this */
#define ICTX_REQUESTVER          0x1

/* Needed for BER-encoding */
#define ASN1_IA5STRING_TAG       0x16

/***************************************************************************
 *   the ASN.1 struct for the remote audit request and response:           *
 *                                                                         *
 *   RequestValue ::= SEQUENCE  {                                          *
 *       RequestVersion    INTEGER,                                        *
 *       ItemList    SEQUENCE OF                                           *
 *           Item    SEQUENCE {                                            *
 *               ItemVersion    INTEGER,                                   *
 *               ItemTag        INTEGER,                                   *
 *               LinkValue    OCTET STRING SIZE(8),                        *
 *               Violation    BOOLEAN,                                     *
 *               Event        INTEGER,                                     *
 *               Qualifier    INTEGER,                                     *
 *               Class        IA5String,                                   *
 *               Resource    IA5String,                                    *
 *               LogString    IA5String,                                   *
 *               DatafieldList    SEQUENCE OF                              *
 *                   DataField    SEQUENCE {                               *
 *                       TYPE    INTEGER,                                  *
 *                       VALUE    IA5STRING                                *
 *                   }                                                     *
 *           }                                                             *
 *   }                                                                     *
 *                                                                         *
 *   Response ::= SEQUENCE {                                               *
 *       Version        INTEGER,                                           *
 *       ResponseCode    INTEGER,                                          *
 *       ItemList    SEQUENCE OF                                           *
 *           Item    SEQUENCE {                                            *
 *               ItemVersion    INTEGER,                                   *
 *               ItemTag        INTEGER,                                   *
 *               MajorCode    INTEGER,                                     *
 *               MinorCode1    INTEGER,                                    *
 *               MinorCode2    INTEGER,                                    *
 *               MinorCode3    INTEGER                                     *
 *           }                                                             *
 *   }                                                                     *
 ***************************************************************************/

/***************************************************************************
 *   z/OS Remote-services Audit Minor return codes meaning

Major Code    Meaning
----------    ---------------------------------------------------------
0-14          - MinorCode1 is the SAF return code
              - MinorCode2 is the RACF return code
              - MinorCode3 is the RACF reason code

16-20         - MinorCode1 identifies the extended operation request
                parameter number (see audit request ASN.1 definition):
                 0 - Item
                 1 - ItemVersion
                 2 - ItemTag
                 3 - LinkValue
                 4 - Violation
                 5 - Event
                 6 - Qualifier
                 7 - Class
                 8 - Resource
                 9 - LogString
                10 - DataFieldList
                11 - DataField *
                12 - TYPE *
                13 - VALUE *
              - MinorCode2 indicates one of the Following:
                32 - incorrect length
                36 - incorrect value
                40 - encoding error
              - MinorCode3 has no defined meaning

24-100        - MinorCode1 has no defined meaning
              - MinorCode2 has no defined meaning
              - MinorCode3 has no defined meaning

* There can be multiple DataField, TYPEs and VALUEs in a request. If any of them is bad
  you get the same 11, 12 or 13 MinorCode1. There is no further breakdown of which one
  is bad.

 ***************************************************************************/

/***************************************************************************
 *   Audit Request 'event' field meaning                                   *
 ***************************************************************************/
#define ZOS_REMOTE_EVENT_AUTHENTICATION            0x1
#define ZOS_REMOTE_EVENT_AUTHORIZATION             0x2
#define ZOS_REMOTE_EVENT_AUTHORIZATION_MAPPING     0x3
#define ZOS_REMOTE_EVENT_KEY_MGMT                  0x4
#define ZOS_REMOTE_EVENT_POLICY_MGMT               0x5
#define ZOS_REMOTE_EVENT_ADMIN_CONFIG              0x6
#define ZOS_REMOTE_EVENT_ADMIN_ACTION              0x7

/***************************************************************************
 *   Audit Request 'qualifier' field meaning                               *
 ***************************************************************************/
#define ZOS_REMOTE_QUALIF_SUCCESS                  0x0
#define ZOS_REMOTE_QUALIF_INFO                     0x1
#define ZOS_REMOTE_QUALIF_WARN                     0x2
#define ZOS_REMOTE_QUALIF_FAIL                     0x3

/***************************************************************************
 *   Relocate types for Audit Request                                      *
 ***************************************************************************/
/* SAF identifier for bind user */
#define ZOS_REMOTE_RELOC_SAF_BIND_USER             100

/* Reguestor's bind user identifier */
#define ZOS_REMOTE_RELOC_REQ_BIND_USER             101

/* Originating security domain */
#define ZOS_REMOTE_RELOC_ORIG_SECURITY             102

/* Originating registry / realm */
#define ZOS_REMOTE_RELOC_ORIG_REALM                103

/* Originating user name */
#define ZOS_REMOTE_RELOC_ORIG_USER                 104

/* Mapped security domain */
#define ZOS_REMOTE_RELOC_MAPPED_SECURITY           105

/* Mapped registry / realm */
#define ZOS_REMOTE_RELOC_MAPPED_REALM              106

/* Mapped user name */
#define ZOS_REMOTE_RELOC_MAPPED_USER               107

/* Operation performed */
#define ZOS_REMOTE_RELOC_OPERATION                 108

/* Mechanism / object name */
#define ZOS_REMOTE_RELOC_OBJECT                    109

/* Method  / function used */
#define ZOS_REMOTE_RELOC_FUNCTION                  110

/* Key / certificate name */
#define ZOS_REMOTE_RELOC_CERTIFICATE               111

/* Caller subject initiating security event  */
#define ZOS_REMOTE_RELOC_INITIATING_EVENT          112

/* Date and time security event occurred  */
#define ZOS_REMOTE_RELOC_TIMESTAMP                 113

/* Application specific data. (i.e. Other) */
#define ZOS_REMOTE_RELOC_OTHER                     114

/***************************************************************************
 *   z/OS Remote-services Audit Major return codes                         *
 ***************************************************************************/
#define ZOS_REMOTE_MAJOR_SUCCESS                   0

/* Event was logged, with warnings */
#define ZOS_REMOTE_MAJOR_WARNINGMODE               2

/* No logging required
   No audit controls are set to require it */
#define ZOS_REMOTE_MAJOR_NOTREQ                    3

/* Class not active/ractlisted, 
   covering profile not found or 
   RACF is not installed */
#define ZOS_REMOTE_MAJOR_UNDETERMINED              4

/* The user does not have authority the R_auditx service.
    The userid associated with the LDAP server must have
    at least READ access to the FACILITY class profile IRR.RAUDITX. */
#define ZOS_REMOTE_MAJOR_UNAUTHORIZED              8


/* The R_auditx service returned an unexpected error.
   Compare the returned minor codes with the SAF RACF codes
   documented in Security Server Callable Services */
#define ZOS_REMOTE_MAJOR_RACROUTE                  12

/* A value specified in the extended operation request is 
   incorrect or unsupported. Check the returned minor codes
   to narrow the reason */
#define ZOS_REMOTE_MAJOR_VAL_ERR                   16

/* A DER decoding error was encountered in an item.
   Processing Terminated. Partial results may be returned */
#define ZOS_REMOTE_MAJOR_ENC_ERR                   20

/* The requestor does not have sufficient authority for the
   requested function. The userid associated with the LDAP bind
   user must have at least READ access to the FACILITY class
   profile IRR.LDAP.REMOTE.AUDIT. */
#define ZOS_REMOTE_MAJOR_UNSUF_AUTH                24

/* No items are found within the ItemList sequence of the extended
   operation request, so no response items are returned */
#define ZOS_REMOTE_MAJOR_EMPTY                     28

/* Invalid RequestVersion */
#define ZOS_REMOTE_MAJOR_INVALID_VER               61

/* An internal error was encountered within the ICTX component */
#define ZOS_REMOTE_MAJOR_INTERNAL_ERR              100

/***************************************************************************
 *   Some standard sizes for remote audit request items                    *
 ***************************************************************************/
#define ZOS_REMOTE_LINK_VALUE_SIZE                 8
#define ZOS_REMOTE_CLASS_SIZE                      8
#define ZOS_REMOTE_RESOURCE_SIZE                   240
#define ZOS_REMOTE_LOGSTRING_SIZE                  200


/***************************************************************************
 *   Some standard Error defines                                           *
 ***************************************************************************/
#define ICTX_SUCCESS                         0x00

/* maybe a temporary failure? */
#define ICTX_E_TRYAGAIN                      0x01

/* permanent failure - abort event submission */
#define ICTX_E_ABORT                         0x02

/* Fatal failure - abort program */
#define ICTX_E_FATAL                         0x03

/* generic error */
#define ICTX_E_ERROR                         0x10

/***************************************************************************
 *   structure representing an z/OS Remote-services session                *
 ***************************************************************************/
typedef struct opaque
{
    char *server;
    unsigned int port;
    char *user;
    char *password;
    unsigned int timeout;
    LDAP *ld;
    int connected;
} ZOS_REMOTE;

/***************************************************************************
 *   LDAP XOP operations                                                   *
 ***************************************************************************/
/* 
 * Initializes z/OS Remote-services (LDAP to ITDS) connection,
 * binds to ITDS Server using configured RACF ID
 * Args are:
 * server, bind user, bind password, server port, timeout
 * Caller must call zos_remote_destroy() to free memory allocation
 */
int zos_remote_init(ZOS_REMOTE *, const char *, int, const char *, 
			const char *, int);

/* 
 * Uninitializes z/OS Remote-services (LDAP) connection
 */
void zos_remote_destroy(ZOS_REMOTE *);

/* 
 * sync submit request - possibly reconnect to server
 * if the connection if found to be dead
 */
int submit_request_s(ZOS_REMOTE *, BerElement *);


#endif                          /* _ZOS_REMOTE_LDAP_H */
