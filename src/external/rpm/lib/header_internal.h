#ifndef H_HEADER_INTERNAL
#define H_HEADER_INTERNAL

/** \ingroup header
 * \file header_internal.h
 */

#include <rpm/header.h>
#include <rpm/rpmcrypto.h>

typedef struct entryInfo_s * entryInfo;
typedef struct hdrblob_s * hdrblob;
struct hdrblob_s {
    uint32_t *ei;
    uint32_t il;
    uint32_t dl;
    entryInfo pe;
    uint32_t pvlen;
    uint8_t *dataStart;
    uint8_t *dataEnd;

    rpmTagVal regionTag;
    uint32_t ril;
    uint32_t rdl;
};

RPM_GNUC_INTERNAL
hdrblob hdrblobCreate(void);

RPM_GNUC_INTERNAL
hdrblob hdrblobFree(hdrblob blob);

RPM_GNUC_INTERNAL
rpmRC hdrblobInit(const void *uh, size_t uc,
		rpmTagVal regionTag, int exact_size,
		struct hdrblob_s *blob, char **emsg);

RPM_GNUC_INTERNAL
rpmRC hdrblobRead(FD_t fd, int magic, int exact_size, rpmTagVal regionTag, hdrblob blob, char **emsg);

RPM_GNUC_INTERNAL
rpmRC hdrblobImport(hdrblob blob, int fast, Header *hdrp, char **emsg);

RPM_GNUC_INTERNAL
rpmRC hdrblobGet(hdrblob blob, uint32_t tag, rpmtd td);

RPM_GNUC_INTERNAL
void hdrblobDigestUpdate(rpmDigestBundle bundle, struct hdrblob_s *blob);

/** \ingroup header
 * Set header instance (rpmdb record number)
 * @param h		header
 * @param instance	record number
 */
RPM_GNUC_INTERNAL
void headerSetInstance(Header h, unsigned int instance);

/* Package IO helper to consolidate partial read and error handling */
RPM_GNUC_INTERNAL
ssize_t Freadall(FD_t fd, void * buf, ssize_t size);

RPM_GNUC_INTERNAL
int headerIsSourceHeuristic(Header h);

#endif  /* H_HEADER_INTERNAL */
