/* errormsg.h --
 * Copyright 2008 FUJITSU Inc.
 * Copyright 2012-17 Red Hat
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Zhang Xiliang <zhangxiliang@cn.fujitsu.com>
 *      Steve Grubb <sgrubb@redhat.com>
 *      Richard Guy Briggs <rgb@redhat.com>
 */

struct msg_tab {
    int key; /* error number */
    /*
     * the field string position in the error message
     * 0: don't output field string
     * 1: output field string before error message
     * 2: output field string after error message
     */
    int position;
    const char	*cvalue;
};

#ifndef NO_TABLES
#define EAU_OPMISSING		1
#define EAU_FIELDUNKNOWN	2
#define EAU_ARCHMISPLACED	3
#define EAU_ARCHUNKNOWN		4
#define EAU_ELFUNKNOWN		5
#define EAU_ARCHNOBIT		6
#define EAU_EXITONLY		7
#define EAU_MSGTYPEUNKNOWN	8
#define EAU_MSGTYPEEXCLUDEUSER	9
#define EAU_UPGRADEFAIL		10
#define EAU_STRTOOLONG		11
#define EAU_MSGTYPECREDEXCLUDE	12
#define EAU_OPEQNOTEQ		13
#define EAU_PERMRWXA		14
#define EAU_ERRUNKNOWN		15
#define EAU_FILETYPEUNKNOWN	16
#define EAU_EXITENTRYONLY	17
#define EAU_KEYDEP		19
#define EAU_FIELDVALMISSING	20
#define EAU_FIELDVALNUM		21
#define EAU_FIELDNAME		22
#define EAU_COMPFIELDNAME	24
#define EAU_COMPVAL		25
#define EAU_COMPFIELDUNKNOWN	26
#define EAU_COMPVALUNKNOWN	27
#define EAU_FIELDTOOMANY	28
#define EAU_OPEQ		29
#define EAU_FIELDNOSUPPORT	30
#define EAU_FIELDNOFILTER	31
#define EAU_FILTERMISSING	32
#define EAU_COMPINCOMPAT	33
#define EAU_FIELDUNAVAIL	34
#define EAU_FILTERNOSUPPORT	35
#define EAU_FSTYPEUNKNOWN	36
static const struct msg_tab err_msgtab[] = {
    { -EAU_OPMISSING,		2, "-F missing operation for" },
    { -EAU_FIELDUNKNOWN,	2, "-F unknown field:" },
    { -EAU_ARCHMISPLACED,	1, "must be before -S" },
    { -EAU_ARCHUNKNOWN,		1, "machine type not found" },
    { -EAU_ELFUNKNOWN,		1, "elf mapping not found" },
    { -EAU_ARCHNOBIT,		1, "requested bit level not supported by machine" },
    { -EAU_EXITONLY,		1, "can only be used with exit filter list" },
    { -EAU_MSGTYPEUNKNOWN,	2, "-F unknown message type -" },
    { -EAU_MSGTYPEEXCLUDEUSER,	0, "msgtype field can only be used with exclude or user filter list" },
    { -EAU_UPGRADEFAIL,		0, "Failed upgrading rule" },
    { -EAU_STRTOOLONG,		0, "String value too long" },
    { -EAU_MSGTYPECREDEXCLUDE,	0, "Only msgtype, *uid, *gid, pid, and subj* fields can be used with exclude filter" },
    { -EAU_OPEQNOTEQ,		1, "only takes = or != operators" },
    { -EAU_PERMRWXA,		0, "Permission can only contain  \'rwxa\'" },
    { -EAU_ERRUNKNOWN,		2, "-F unknown errno -"},
    { -EAU_FILETYPEUNKNOWN,	2, "-F unknown file type - " },
    { -EAU_EXITENTRYONLY,	1, "can only be used with exit and entry filter list" },
    { -18,			1, "" }, // Deprecated don't reuse
    { -EAU_KEYDEP,		0, "Key field needs a watch, syscall or exe path given prior to it" },
    { -EAU_FIELDVALMISSING,	2, "-F missing value after operation for" },
    { -EAU_FIELDVALNUM,		2, "-F value should be number for" },
    { -EAU_FIELDNAME,		2, "-F missing field name before operator for" },
    { -23,			2, "" }, // Deprecated don't reuse
    { -EAU_COMPFIELDNAME,	2, "-C missing field name before operator for" },
    { -EAU_COMPVAL,		2, "-C missing value after operation for "},
    { -EAU_COMPFIELDUNKNOWN,	2, "-C unknown field:" },
    { -EAU_COMPVALUNKNOWN,	2, "-C unknown right hand value for comparison with:" },
    { -EAU_FIELDTOOMANY,	2, "Too many fields in rule:" },
    { -EAU_OPEQ,		1, "only takes = operator" },
    { -EAU_FIELDNOSUPPORT,	2, "Field option not supported by kernel:" },
    { -EAU_FIELDNOFILTER,	1, "must be used with exclude, user, or exit filter" },
    { -EAU_FILTERMISSING,	0, "filter is missing from rule" },
    { -EAU_COMPINCOMPAT,	2, "-C incompatible comparison" },
    { -EAU_FIELDUNAVAIL,	1, "field is not valid for the filter" },
    { -EAU_FILTERNOSUPPORT,	1, "filter is not supported by the kernel" },
    { -EAU_FSTYPEUNKNOWN,	2, "file system type is unknown for field:" },
};
#endif
