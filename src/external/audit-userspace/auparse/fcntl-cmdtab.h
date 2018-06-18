/* fcntl-cmdtab.h --
 * Copyright 2007,2012-13 Red Hat Inc., Durham, North Carolina.
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
 *      Steve Grubb <sgrubb@redhat.com>
 * Location: include/uapi/asm-generic/fcntl.h <17
 *           include/uapi/linux/fcntl.h >= 1024
 */

_S(0,		"F_DUPFD" )
_S(1,		"F_GETFD" )
_S(2,		"F_SETFD" )
_S(3,		"F_GETFL" )
_S(4,		"F_SETFL" )
_S(5,		"F_GETLK" )
_S(6,		"F_SETLK" )
_S(7,		"F_SETLKW" )
_S(8,		"F_SETOWN" )
_S(9,		"F_GETOWN" )
_S(10,		"F_SETSIG" )
_S(11,		"F_GETSIG" )
_S(12,		"F_GETLK64" )
_S(13,		"F_SETLK64" )
_S(14,		"F_SETLKW64" )
_S(15,		"F_SETOWN_EX" )
_S(16,		"F_GETOWN_EX" )
_S(17,		"F_GETOWNER_UIDS" )
_S(1024,	"F_SETLEASE" )
_S(1025,	"F_GETLEASE" )
_S(1026,	"F_NOTIFY" )
_S(1029,	"F_CANCELLK" )
_S(1030,	"F_DUPFD_CLOEXEC" )
_S(1031,	"F_SETPIPE_SZ" )
_S(1032,	"F_GETPIPE_SZ" )
_S(1033,	"F_ADD_SEALS" )
_S(1034,	"F_GET_SEALS" )
_S(1035,	"F_GET_RW_HINT" )
_S(1036,	"F_SET_RW_HINT" )
_S(1037,	"F_GET_FILE_RW_HINT" )
_S(1038,	"F_SET_FILE_RW_HINT" )
