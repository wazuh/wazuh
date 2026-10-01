#ifndef _RPMBUILD_MISC_H
#define _RPMBUILD_MISC_H

#include <sys/types.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmds.h>

/** \ingroup rpmbuild
 * Truncate comment lines.
 * @param s		skip white space, truncate line at '#'
 * @return		1 on comment lines, 0 otherwise
 */
RPM_GNUC_INTERNAL
int handleComments(char * s);

RPM_GNUC_INTERNAL
struct Source *findSource(rpmSpec spec, uint32_t num, int flag);

/** \ingroup rpmstring
 */
typedef struct StringBufRec *StringBuf;

/** \ingroup rpmstring
 */
RPM_GNUC_INTERNAL
StringBuf newStringBuf(void);

/** \ingroup rpmstring
 */
RPM_GNUC_INTERNAL
StringBuf freeStringBuf( StringBuf sb);

/** \ingroup rpmstring
 */
RPM_GNUC_INTERNAL
const char * getStringBuf(StringBuf sb);

/** \ingroup rpmstring
 */
RPM_GNUC_INTERNAL
void stripTrailingBlanksStringBuf(StringBuf sb);

/** \ingroup rpmstring
 */
#define appendStringBuf(sb, s)     appendStringBufAux(sb, s, 0)

/** \ingroup rpmstring
 */
#define appendLineStringBuf(sb, s) appendStringBufAux(sb, s, 1)

/** \ingroup rpmstring
 */
RPM_GNUC_INTERNAL
void appendStringBufAux(StringBuf sb, const char * s, int nl);

/** \ingroup rpmbuild
 * Parse an unsigned number.
 * @param		line from spec file
 * @param[out] res		pointer to uint32_t
 * @return		0 on success, -1 on failure
 */
RPM_GNUC_INTERNAL
int parseUnsignedNum(const char * line, uint32_t * res);

#endif /* _RPMBUILD_MISC_H */
