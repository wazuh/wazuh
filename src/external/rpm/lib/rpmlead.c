/** \ingroup lead
 * \file lib/rpmlead.c
 */

#include "system.h"

#include <errno.h>
#include <netinet/in.h>

#include <rpm/rpmlib.h>		/* rpmGetOs/ArchInfo() */
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>

#include "signature.h"
#include "header_internal.h"	/* Freadall() */
#include "rpmlead.h"

#include "debug.h"

/* A long time ago in a galaxy far far away, signatures were not in a header */
#define RPMSIGTYPE_HEADERSIG 5

static unsigned char const lead_magic[] = {
    RPMLEAD_MAGIC0, RPMLEAD_MAGIC1, RPMLEAD_MAGIC2, RPMLEAD_MAGIC3
};

/** \ingroup lead
 * The lead data structure.
 * The lead needs to be 8 byte aligned.
 * @deprecated The lead (except for signature_type) is legacy.
 * @todo Don't use any information from lead.
 */
struct rpmlead_s {
    unsigned char magic[4];
    unsigned char major;
    unsigned char minor;
    short type;
    short archnum;
    char name[66];
    short osnum;
    short signature_type;       /*!< Signature header type (RPMSIG_HEADERSIG) */
    char reserved[16];      /*!< Pad to 96 bytes -- 8 byte aligned! */
};

static int rpmLeadFromHeader(Header h, struct rpmlead_s *l)
{
    if (h != NULL) {
	int archnum, osnum;
	char * nevr = headerGetAsString(h, RPMTAG_NEVR);

	/* FIXME: should grab these from header instead (RhBug:717898) */
	rpmGetArchInfo(NULL, &archnum);
	rpmGetOsInfo(NULL, &osnum);

	memset(l, 0, sizeof(*l));
	l->major = 3;
	l->minor = 0;
	l->archnum = archnum;
	l->osnum = osnum;
	l->signature_type = RPMSIGTYPE_HEADERSIG;
	l->type = (headerIsSource(h) ? 1 : 0);

	memcpy(l->magic, lead_magic, sizeof(l->magic));
	rstrlcpy(l->name, nevr, sizeof(l->name));

	free(nevr);
    }

    return (h != NULL);
}

/* The lead needs to be 8 byte aligned */
rpmRC rpmLeadWrite(FD_t fd, Header h)
{
    rpmRC rc = RPMRC_FAIL;
    struct rpmlead_s l;

    if (rpmLeadFromHeader(h, &l)) {
	
	l.type = htons(l.type);
	l.archnum = htons(l.archnum);
	l.osnum = htons(l.osnum);
	l.signature_type = htons(l.signature_type);
	    
	if (Fwrite(&l, 1, sizeof(l), fd) == sizeof(l))
	    rc = RPMRC_OK;
    }

    return rc;
}

static rpmRC rpmLeadCheck(struct rpmlead_s *lead, char **msg)
{
    if (memcmp(lead->magic, lead_magic, sizeof(lead_magic))) {
        *msg = xstrdup(_("not an rpm package"));
        return RPMRC_NOTFOUND;
    }
    return RPMRC_OK;
}

rpmRC rpmLeadRead(FD_t fd, char **emsg)
{
    rpmRC rc = RPMRC_OK;
    struct rpmlead_s l;
    char *err = NULL;

    memset(&l, 0, sizeof(l));
    if (Freadall(fd, &l, sizeof(l)) != sizeof(l)) {
	if (Ferror(fd)) {
	    rasprintf(&err, _("read failed: %s (%d)\n"), Fstrerror(fd), errno);
	    rc = RPMRC_FAIL;
	} else {
	    err = xstrdup(_("not an rpm package\n"));
	    rc = RPMRC_NOTFOUND;
	}
    } else {
	l.type = ntohs(l.type);
	l.archnum = ntohs(l.archnum);
	l.osnum = ntohs(l.osnum);
	l.signature_type = ntohs(l.signature_type);
	rc = rpmLeadCheck(&l, &err);
    }

    if (rc != RPMRC_OK) {
	if (emsg != NULL)
	    *emsg = err;
	else
	    free(err);
    }

    return rc;
}
