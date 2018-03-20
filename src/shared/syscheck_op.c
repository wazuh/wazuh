/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2016 Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscheck_op.h"

/* Local variables */
_sdb sdb;

/* Parse c_sum string. Returns 0 if success, 1 when c_sum denotes a deleted file
   or -1 on failure. */
int sk_decode_sum(sk_sum_t *sum, char *c_sum) {
    char *c_perm;
    char *c_mtime;
    char *c_inode;

    memset(sum, 0, sizeof(sk_sum_t));

    if (c_sum[0] == '-' && c_sum[1] == '1')
        return 1;

    sum->size = c_sum;

    if (!(c_perm = strchr(c_sum, ':')))
        return -1;

    *(c_perm++) = '\0';

    if (!(sum->uid = strchr(c_perm, ':')))
        return -1;

    *(sum->uid++) = '\0';
    sum->perm = atoi(c_perm);

    if (!(sum->gid = strchr(sum->uid, ':')))
        return -1;

    *(sum->gid++) = '\0';

    if (!(sum->md5 = strchr(sum->gid, ':')))
        return -1;

    *(sum->md5++) = '\0';

    if (!(sum->sha1 = strchr(sum->md5, ':')))
        return -1;

    *(sum->sha1++) = '\0';

    // New fields: user name, group name, modification time and inode

    if (!(sum->uname = strchr(sum->sha1, ':')))
        return 0;

    *(sum->uname++) = '\0';

    if (!(sum->gname = strchr(sum->uname, ':')))
        return -1;

    *(sum->gname++) = '\0';

    if (!(c_mtime = strchr(sum->gname, ':')))
        return -1;

    *(c_mtime++) = '\0';

    if (!(c_inode = strchr(c_mtime, ':')))
        return -1;

    *(c_inode++) = '\0';

    sum->sha256 = NULL;
    
    if ((sum->sha256 = strchr(c_inode, ':')))
        *(sum->sha256++) = '\0'; 

    sum->mtime = atol(c_mtime);
    sum->inode = atol(c_inode);
    return 0;
}

void sk_fill_event(Eventinfo *lf, const char *f_name, const sk_sum_t *sum) {
    int i;

    os_strdup(f_name, lf->filename);
    os_strdup(sum->size, lf->size_after);
    lf->perm_after = sum->perm;
    os_strdup(sum->uid, lf->owner_after);
    os_strdup(sum->gid, lf->gowner_after);
    os_strdup(sum->md5, lf->md5_after);
    os_strdup(sum->sha1, lf->sha1_after);

    if (sum->uname)
        os_strdup(sum->uname, lf->uname_after);

    if (sum->gname)
        os_strdup(sum->gname, lf->gname_after);

    lf->mtime_after = sum->mtime;
    lf->inode_after = sum->inode;

    if(sum->sha256)
        os_strdup(sum->sha256, lf->sha256_after);

    /* Fields */

    lf->nfields = SK_NFIELDS;

    for (i = 0; i < SK_NFIELDS; i++)
        os_strdup(sdb.syscheck_dec->fields[i], lf->fields[i].key);

    os_strdup(f_name, lf->fields[SK_FILE].value);
    os_strdup(sum->size, lf->fields[SK_SIZE].value);
    os_calloc(7, sizeof(char), lf->fields[SK_PERM].value);
    snprintf(lf->fields[SK_PERM].value, 7, "%06o", sum->perm);
    os_strdup(sum->uid, lf->fields[SK_UID].value);
    os_strdup(sum->gid, lf->fields[SK_GID].value);
    os_strdup(sum->md5, lf->fields[SK_MD5].value);
    os_strdup(sum->sha1, lf->fields[SK_SHA1].value);

    if (sum->uname)
        os_strdup(sum->uname, lf->fields[SK_UNAME].value);

    if (sum->gname)
        os_strdup(sum->gname, lf->fields[SK_GNAME].value);

    if (sum->inode) {
        os_calloc(20, sizeof(char), lf->fields[SK_INODE].value);
        snprintf(lf->fields[SK_INODE].value, 20, "%ld", sum->inode);
    }

    if(sum->sha256)
        os_strdup(sum->sha256, lf->fields[SK_SHA256].value);
}

int sk_build_sum(const sk_sum_t * sum, char * output, size_t size) {
    int r;

    if (sum->uname || sum->gname || sum->mtime || sum->inode) {
        r = snprintf(output, size, "%s:%d:%s:%s:%s:%s:%s:%s:%ld:%ld", sum->size, sum->perm, sum->uid, sum->gid, sum->md5, sum->sha1, sum->uname, sum->gname, sum->mtime, sum->inode);
    } else {
        r = snprintf(output, size, "%s:%d:%s:%s:%s:%s", sum->size, sum->perm, sum->uid, sum->gid, sum->md5, sum->sha1);
    }

    return r < (int)size ? 0 : -1;
}
