#ifndef H_MISC
#define H_MISC

/**
 * \file misc.h
 *
 */

#include <string.h>
#include <rpm/rpmtypes.h>
#include <rpm/header.h>		/* for headerGetFlags typedef, duh.. */
#include "rpmfs.h"

typedef const struct headerFmt_s * headerFmt;

/* known arch? */
RPM_GNUC_INTERNAL
int rpmIsKnownArch(const char *name);

RPM_GNUC_INTERNAL
char * rpmVerifyString(uint32_t verifyResult, const char *pad);

RPM_GNUC_INTERNAL
char * rpmFFlagsString(uint32_t fflags);

typedef int (*headerTagTagFunction) (Header h, rpmtd td, headerGetFlags hgflags);

RPM_GNUC_INTERNAL
headerTagTagFunction rpmHeaderTagFunc(rpmTagVal tag);

RPM_GNUC_INTERNAL
headerFmt rpmHeaderFormatByName(const char *fmt);

RPM_GNUC_INTERNAL
headerFmt rpmHeaderFormatByValue(rpmtdFormats fmt);

RPM_GNUC_INTERNAL
char * rpmHeaderFormatCall(headerFmt fmt, rpmtd td);

RPM_GNUC_INTERNAL
int headerFindSpec(Header h);

/**
 * Relocate files in header.
 * @todo multilib file dispositions need to be checked.
 * @param relocs		relocations
 * @param numRelocations	number of relocations
 * @param fs			file state set
 * @param h			package header to relocate
 */
RPM_GNUC_INTERNAL
void rpmRelocateFileList(rpmRelocation *relocs, int numRelocations, rpmfs fs, Header h);

RPM_GNUC_INTERNAL
int rpmRelocateSrpmFileList(Header h, const char *rootDir);

RPM_GNUC_INTERNAL
void rpmRelocationBuild(Header h, rpmRelocation *rawrelocs,
		int *rnrelocs, rpmRelocation **rrelocs, uint8_t **rbadrelocs);

#endif	/* H_MISC */
