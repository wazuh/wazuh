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

#include "zos-remote-ldap.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zos-remote-log.h"

/***************************************************************************
 *   Audit response struct                                                 *
 ***************************************************************************/
typedef struct audit_resp_item
{
        ber_int_t version;      /* Version of Response data itself */
        ber_int_t itemTag;      /* Copy of itemTag from Operation */
        ber_int_t majorCode;    /* Majorcode. Main return code of this Outcome */
        ber_int_t minorCode1;   /* minorCode1. SAFRc   or other Rc */
        ber_int_t minorCode2;   /* minorCode2. RacfRc  or other Rc */
        ber_int_t minorCode3;   /* minorCode3. RacfRsn or other Rc */
} audit_resp_item_t;

typedef struct audit_response
{
        ber_int_t respVersion;          /* Overall version */
        ber_int_t respMajor;            /* Overall major code */
        unsigned int numItems;          /* Number of response items */
        audit_resp_item_t **itemList;   /* response ItemList */
} audit_response_t;


/***************************************************************************
 *   z/OS Remote-services Major return code handling                       *
 ***************************************************************************/
struct zos_remote_error
{
        int code;
        char *str;
};

static struct zos_remote_error zos_remote_errlist[] = {
        {ZOS_REMOTE_MAJOR_SUCCESS,      "Success"},
        {ZOS_REMOTE_MAJOR_WARNINGMODE,  "WARNINGMODE - Event was logged, with warnings"},
        {ZOS_REMOTE_MAJOR_NOTREQ,       "NOTREQ - No logging required"},
        {ZOS_REMOTE_MAJOR_UNDETERMINED, "UNDETERMINED - Undetermined result"},
        {ZOS_REMOTE_MAJOR_UNAUTHORIZED, "UNAUTHORIZED - The user does not have authority the R_auditx service"},
        {ZOS_REMOTE_MAJOR_RACROUTE,     "RACROUTE - The R_auditx service returned an unexpected error"},
        {ZOS_REMOTE_MAJOR_VAL_ERR,      "VAL_ERR - Value error in request"},
        {ZOS_REMOTE_MAJOR_ENC_ERR,      "ENC_ERR - DER decoding error in request"},
        {ZOS_REMOTE_MAJOR_UNSUF_AUTH,   "UNSUF_AUTH - The user has unsuficient authority for the requested function"},
        {ZOS_REMOTE_MAJOR_EMPTY,        "EMPTY - Empty request received - No items found within the ItemList"},
        {ZOS_REMOTE_MAJOR_INVALID_VER,  "INVALID_VER - Invalid RequestVersion"},
        {ZOS_REMOTE_MAJOR_INTERNAL_ERR, "INTERNAL_ERR - An internal error was encountered within the ICTX component"},
        {-1, NULL}
};

/***************************************************************************
 *   Internal functions prototypes                                         *
 ***************************************************************************/
static int _zos_remote_init(ZOS_REMOTE *);
static void _zos_remote_destroy(ZOS_REMOTE *);
static int zos_remote_connect(ZOS_REMOTE *);
static void zos_remote_disconnect(ZOS_REMOTE *);
static int submit_xop_s(ZOS_REMOTE *, struct berval *);
static int decode_response(audit_response_t *, struct berval *);

/***************************************************************************
 *   Exported functions                                                    *
 ***************************************************************************/
int submit_request_s(ZOS_REMOTE *zos_remote, BerElement *ber)
{
        int rc, retry = 1;                /* retry once and give up */
        struct berval bv;

        rc = ber_flatten2(ber, &bv, 0);   /* 0 = Use ber's buffer */
        if (rc == -1) {
                log_err("Error flattening BER element");
                return ICTX_E_ABORT;
        }

retry:
        rc = submit_xop_s(zos_remote, &bv);
        switch (rc) {
        case ICTX_SUCCESS:
                break;
        case ICTX_E_TRYAGAIN:
                /* 
                 * Usually means that the server connection timed-out
                 * So we flush the LDAP connection by unsetting the
                 * 'connected' flag and trying again.
                 */
                if (retry > 0) {
                        log_debug("Connection seems down - retrying");
                        retry--;
                        _zos_remote_destroy(zos_remote);
                        rc = _zos_remote_init(zos_remote);
                        if (rc != ICTX_SUCCESS)
                                log_err("Error - failed to re-initialize LDAP session");
                        else
                                goto retry;        /* go to submit_xop_s once more */
                }
                log_err("Can't establish connection");
                break;
        case ICTX_E_ABORT:
                break;
        default:
                log_err("Event resulted failure, code: 0x%x", rc);
        }

        return rc;
}

int zos_remote_init(ZOS_REMOTE *zos_remote, const char *server, int port,
              const char *user, const char *password, int timeout)
{       
        zos_remote->server = strdup(server);
        zos_remote->port = port;
        zos_remote->user = strdup(user);
        zos_remote->password = strdup(password);
        zos_remote->timeout = timeout;
        zos_remote->connected = 0;
        
        if (!zos_remote->server || !zos_remote->user || !zos_remote->password) {
                log_err("Error allocating memory for session members");
                return ICTX_E_FATAL;
        }

        return _zos_remote_init(zos_remote);
}

void zos_remote_destroy(ZOS_REMOTE *zos_remote)
{
        _zos_remote_destroy(zos_remote);

        free(zos_remote->server);
        free(zos_remote->user);
        free(zos_remote->password);
}

char *zos_remote_err2string(int err)
{
        int i;

        for (i = 0; zos_remote_errlist[i].str != NULL; i++) {
                if (err == zos_remote_errlist[i].code)
                        return zos_remote_errlist[i].str;
        }
        return "Unknown error";
}

/***************************************************************************
 *   Internal Functions                                                    *
 ***************************************************************************/
static int _zos_remote_init(ZOS_REMOTE *zos_remote)
{
        int version, rc;
        char *uri = NULL;
            
#ifdef LDAP_DEPRECATED

        log_debug("Initializing z/OS Remote-services LDAP connection at ldap://%s:%d",
                  zos_remote->server, zos_remote->port);
        zos_remote->ld = ldap_init(zos_remote->server
                             zos_remote->port ? zos_remote->port : LDAP_PORT);
        if (zos_remote->ld == NULL) {
                log_err("Error initializing LDAP session: %s",
                        strerror(errno));
                rc = ICTX_E_FATAL;
                goto end;
        }
#else
        /* build ldap URI */
        if (zos_remote->port == 0 || zos_remote->port == LDAP_PORT)
                rc = asprintf(&uri, "ldap://%s", zos_remote->server);
        else
                rc = asprintf(&uri, "ldap://%s:%d", zos_remote->server,
                              zos_remote->port);

        if (rc == -1) {
                log_err("Out of memory building LDAP server URI");
                rc = ICTX_E_FATAL;
                uri = NULL;
                goto end;
        }

        log_debug("Initializing z/OS Remote-services LDAP connection at %s", uri);
        /* Get a handle to an LDAP connection */
        rc = ldap_initialize(&zos_remote->ld, uri);
        if (rc != LDAP_SUCCESS) {
                log_err("Error initializing LDAP session: %s",
                        ldap_err2string(rc));
                rc = ICTX_E_FATAL;
                goto free_uri;
        }
#endif

        /* 
         * Ensure the LDAP protocol version supported by the client
         * to 3. (Extended operations are part of version 3). 
         */
        rc = ldap_get_option(zos_remote->ld, LDAP_OPT_PROTOCOL_VERSION,
                             &version);
        if (rc != LDAP_OPT_SUCCESS) {
                log_err("Error getting LDAP session options");
                rc = ICTX_E_FATAL;
                goto unbind;
        }

        if (version < LDAP_VERSION3) {
                log_debug("Setting LDAP session version to %d",
                          LDAP_VERSION3);
                version = LDAP_VERSION3;
                rc = ldap_set_option(zos_remote->ld, LDAP_OPT_PROTOCOL_VERSION,
                                     &version);
                if (rc != LDAP_OPT_SUCCESS) {
                        log_err("Error setting LDAP session version");
                        rc = ICTX_E_FATAL;
                        goto unbind;
                }
        }

        goto free_uri;

unbind:
        ldap_unbind_ext_s(zos_remote->ld, NULL, NULL);
        zos_remote->ld = NULL;

free_uri:
        free(uri);

end:
        return rc;
}

static void _zos_remote_destroy(ZOS_REMOTE *zos_remote)
{
    zos_remote_disconnect(zos_remote);
    zos_remote->ld = NULL;
}

static int zos_remote_connect(ZOS_REMOTE *zos_remote)
{
        struct berval cred;
        int rc;
        char bindusr[255];

        snprintf(bindusr, 255, "racfid=%s,cn=ictx", zos_remote->user);

        log_debug("Attempting BIND. User '%s', password '<not shown>'",
                  bindusr);

        cred.bv_val = (char *) zos_remote->password;
        cred.bv_len = strlen(zos_remote->password);
        
        rc = ldap_sasl_bind_s(zos_remote->ld, bindusr,
                              LDAP_SASL_SIMPLE, &cred,
                              NULL, NULL, NULL);
        

        switch (rc) {
        case LDAP_SUCCESS:
                log_debug("LDAP BIND succeeded");
                zos_remote->connected = 1;
                rc = ICTX_SUCCESS;
                break;
        case LDAP_SERVER_DOWN:
        case LDAP_BUSY:
        case LDAP_UNAVAILABLE:
        case LDAP_TIMEOUT:
        case LDAP_CONNECT_ERROR:
                log_warn("z/OS Remote-services connection failed: %s",
                         ldap_err2string(rc));
                rc = ICTX_E_TRYAGAIN;
                break;
        default:
                log_err("Error - z/OS Remote-services initialization failed: %s",
                        ldap_err2string(rc));
                rc = ICTX_E_FATAL;
        }

        return rc;
}


static void zos_remote_disconnect(ZOS_REMOTE *zos_remote)
{
        if (zos_remote->ld) {
                log_debug("Unbinding LDAP session");

#ifdef LDAP_DEPRECATED
                ldap_unbind(zos_remote->ld);
#else
                ldap_unbind_ext_s(zos_remote->ld, NULL, NULL);
#endif
        }
        zos_remote->connected = 0;
        
}

/*
 * Sync-submit extended operation given in *bv
 * return ICTX_SUCCESS if submission (and response)
 * succeeded.
 * Log errors using log_err() functions
 */
int submit_xop_s(ZOS_REMOTE *zos_remote, struct berval *bv)
{
        LDAPMessage *result;
        audit_response_t response;
        int rc, errcode, msgId;
        unsigned int i;
        char *errmsg, *oid;
        struct berval *bv_response;
        struct timeval t;

        if (zos_remote->connected == 0) {
                rc = zos_remote_connect(zos_remote);
                if (rc != ICTX_SUCCESS)
                    return rc;
        }

        /* call LDAP - won't block */
        rc = ldap_extended_operation(zos_remote->ld, ICTX_OIDAUDITREQUEST,
                                     bv, NULL, NULL, &msgId);
        if (rc == LDAP_SERVER_DOWN) {
                zos_remote->connected = 0;
                return ICTX_E_TRYAGAIN;
        } else if (rc != LDAP_SUCCESS) {
                log_err("LDAP extended operation submission failure: %s",
                        ldap_err2string(rc));
                return ICTX_E_ABORT;
        } else {
                log_debug("Sent LDAP extended operation request, msgId=0x%x",
                          msgId);
	}

        /* call blocking ldap_result with specified timeout */
        t.tv_sec = zos_remote->timeout;
        t.tv_usec = 0;
        rc = ldap_result(zos_remote->ld, msgId, 1, &t, &result);

        if (rc == -1) {
                /* error in ldap operation */
                ldap_get_option(zos_remote->ld, LDAP_OPT_ERROR_NUMBER, &errcode);
                switch (errcode) {
                case LDAP_SERVER_DOWN:
                        /* Connection may have timed out, let's retry */
                        zos_remote->connected = 0;
                        rc = ICTX_E_TRYAGAIN;
                        break;
                default:
                        log_err("ldap_result unexpected failure: %s (0x%x)",
                                ldap_err2string(rc), rc);
                        rc = ICTX_E_ABORT;
                }
                goto end;
        } else if (rc == 0) {
                /* timeout reached */
                log_warn("LDAP extended operation timed out");
                rc = ICTX_E_ABORT;
                goto end;
        } else if (rc != LDAP_RES_EXTENDED) {
                /* not an extended operation response! */
                log_err("LDAP extended operation resulted in unexpected answer: 0x%x", rc);
                rc = ICTX_E_ABORT;
                goto free_result;
        }

        log_debug("Got LDAP Extended result");
        /* 
         * we have an extended operation result
         * first parse_result will check for errcode, later
         * parse_extended_result will give us the oid and the BER value
         */
        rc = ldap_parse_result(zos_remote->ld, result, &errcode, NULL,
                               &errmsg, NULL, NULL, 0);
        if (rc != LDAP_SUCCESS) {
                log_err("LDAP parse result internal failure (code 0x%x)",
                        rc);
                rc = ICTX_E_ABORT;
                goto free_result;
        }

        if (errcode != LDAP_SUCCESS) {
                log_err("LDAP extended operation failed: %s", errmsg);
                rc = ICTX_E_ABORT;
                goto free_errmsg;
        }

        rc = ldap_parse_extended_result(zos_remote->ld, result, &oid,
                                        &bv_response, 0);
        if (rc != LDAP_SUCCESS) {
                log_err("Failed to parse ldap extended result (code 0x%x)",
                        rc);
                rc = ICTX_E_ABORT;
                goto free_errmsg;
        }

        if (oid && strcmp(oid, ICTX_OIDAUDITRESPONSE) != 0) {
                /* oid == null shouldn't be a problem to log_err */
                log_err("LDAP extended operation returned an invalid oid: %s", oid);
                rc = ICTX_E_ABORT;
                goto free_bv;
        }

        rc = decode_response(&response, bv_response);
        if (rc != ICTX_SUCCESS) {
                log_err("Error decoding extended operation response");
                goto free_bv;
        }

        if (response.respMajor == ZOS_REMOTE_MAJOR_SUCCESS) {
                /* submission was successful, no further processing needed */
                log_debug("Successfully submited Remote audit Request");
                rc = ICTX_SUCCESS;
                goto free_response;
        } else if (response.respMajor == ZOS_REMOTE_MAJOR_EMPTY) {
                /* something is going on. Set error and stop processing */
                log_warn("Warning - LDAP extended operation returned empty result");
                rc = ICTX_E_ABORT;
                goto free_response;
        } else if (response.respMajor == ZOS_REMOTE_MAJOR_WARNINGMODE ||
                   response.respMajor == ZOS_REMOTE_MAJOR_NOTREQ)
                rc = ICTX_SUCCESS;      /* don't fail, but continue processing */
        else
                rc = ICTX_E_ABORT;      /* set return code and continue processing */

        /* If it's not success nor empty, let's check for errors in the response */
        for (i = 0; i < response.numItems; i++) {
                switch ((response.itemList[i])->majorCode) {
                        /* 0 <= Major Code <= 14 */
                case ZOS_REMOTE_MAJOR_SUCCESS:
                        break;
                case ZOS_REMOTE_MAJOR_WARNINGMODE:
                case ZOS_REMOTE_MAJOR_NOTREQ:
                        log_debug("Warning - LDAP extended operation returned '%s' for item %d",
                                 zos_remote_err2string((response.itemList[i])->majorCode),
                                 (response.itemList[i])->itemTag);
                        log_debug("SAF code: 0x%x, RACF code: 0x%x, RACF reason: 0x%x",
                                 (response.itemList[i])->minorCode1,
                                 (response.itemList[i])->minorCode2,
                                 (response.itemList[i])->minorCode3);
                        break;
                case ZOS_REMOTE_MAJOR_UNDETERMINED:
                case ZOS_REMOTE_MAJOR_UNAUTHORIZED:
                case ZOS_REMOTE_MAJOR_RACROUTE:
                        log_err("Error - LDAP extended operation returned '%s' for item %d",
                                zos_remote_err2string((response.itemList[i])->majorCode),
                                (response.itemList[i])->itemTag);
                        log_err("SAF code: 0x%x, RACF code: 0x%x, RACF reason: 0x%x",
                                (response.itemList[i])->minorCode1,
                                (response.itemList[i])->minorCode2,
                                (response.itemList[i])->minorCode3);
                        break;
                        /* 16 <= Major Code <= 20 */
                case ZOS_REMOTE_MAJOR_VAL_ERR:
                case ZOS_REMOTE_MAJOR_ENC_ERR:
                        log_err("Error - LDAP extended operation returned '%s' for item %d",
                                zos_remote_err2string((response.itemList[i])->majorCode),
                                (response.itemList[i])->itemTag);
                        log_err("Item field: %d, reson %d",
                                (response.itemList[i])->
                                minorCode1,
                                (response.itemList[i])->minorCode2);
                        break;
                        /* 24 <= Major code <= 100 */
                case ZOS_REMOTE_MAJOR_UNSUF_AUTH:
                case ZOS_REMOTE_MAJOR_EMPTY:
                case ZOS_REMOTE_MAJOR_INVALID_VER:
                case ZOS_REMOTE_MAJOR_INTERNAL_ERR:
                        log_err("Error - LDAP extended operation returned '%s' for item %d",
                                zos_remote_err2string((response.itemList[i])->majorCode),
                                (response.itemList[i])->itemTag);
                        break;
                default:
                        log_err("Error - LDAP extended operation returned an unknown Major code for item %d", 
                                (response.itemList[i])->majorCode);
                }
        }

free_response:
        for (; response.numItems > 0; response.numItems--)
                free(response.itemList[response.numItems - 1]);
        free(response.itemList);

free_bv:
        if (bv_response)
                ber_bvfree(bv_response);
        if (oid)
                ldap_memfree(oid);

free_errmsg:
        ldap_memfree(errmsg);

free_result:
        ldap_msgfree(result);

end:
        return rc;
}

static int decode_response(audit_response_t * r, struct berval *bv)
{
        BerElement *ber;
        ber_len_t len;
        int rc;

        if (!bv) {
                log_err("LDAP extended operation returned NULL message");
                return ICTX_E_ABORT;
        } else if ((ber = ber_init(bv)) == NULL) {
                log_err("Error initializing BER response data");
                return ICTX_E_ABORT;
        }

        log_debug("---Got an encoded request response:");
        debug_bv(bv);

        r->respVersion = 0;
        r->respMajor = 0;
        r->numItems = 0;
        r->itemList = NULL;

        rc = ber_scanf(ber, "{ii", &r->respVersion, &r->respMajor);
        if (r->respVersion != ICTX_REQUESTVER) {
                log_err("Invalid version returned by z/OS Remote-services server");
                log_err("Should be %d, got %d", ICTX_REQUESTVER,
                        r->respVersion);
                rc = ICTX_E_ABORT;
                goto free_ber;
        }

        if (r->respMajor == ZOS_REMOTE_MAJOR_SUCCESS ||
            r->respMajor == ZOS_REMOTE_MAJOR_EMPTY) {
                rc = ICTX_SUCCESS;
                /* No further processing required */
                goto free_ber;
        }

        /* Inspect ber response otherwise */
        while (ber_peek_tag(ber, &len) == LBER_SEQUENCE) {
                r->numItems++;
                r->itemList = (audit_resp_item_t **) realloc(r->itemList,
                                                             r->numItems *
                                                             sizeof
                                                             (audit_resp_item_t
                                                              *));
                if (errno == ENOMEM) {
                        if (r->itemList)
                                free(r->itemList);
                        rc = ICTX_E_FATAL;
                        goto free_ber;
                }

                audit_resp_item_t *item = (audit_resp_item_t *)
                        malloc(sizeof(audit_resp_item_t));

                if (!item) {
                        rc = ICTX_E_FATAL;
                        goto free_ber;
                }

                rc |= ber_scanf(ber, "{{iiiiii}}",
                                &item->version,
                                &item->itemTag,
                                &item->majorCode,
                                &item->minorCode1, &item->minorCode2,
                                &item->minorCode3);
                r->itemList[r->numItems - 1] = item;
        }
        rc |= ber_scanf(ber, "}");

        if (rc == -1) {
                for (; r->numItems > 0; r->numItems--)
                        free(r->itemList[r->numItems - 1]);
                free(r->itemList);
                rc = ICTX_E_ABORT;
        }
        else
            rc = ICTX_SUCCESS;

free_ber:
        ber_free(ber, 1);

        return rc;
}
