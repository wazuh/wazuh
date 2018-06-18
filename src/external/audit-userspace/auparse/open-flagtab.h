/* open-flagtab.h --
 * Copyright 2007,2012-14 Red Hat Inc., Durham, North Carolina.
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
 * Location: include/uapi/asm-generic/fcntl.h
 */

// Handled in the code: _S(00,		"O_RDONLY" )
_S(01,		"O_WRONLY" )
_S(02,		"O_RDWR" )
_S(0100,	"O_CREAT")
_S(0200,	"O_EXCL" )
_S(0400,	"O_NOCTTY" )
_S(01000,	"O_TRUNC" )
_S(02000,	"O_APPEND" )
_S(04000,	"O_NONBLOCK" )
_S(010000,	"O_DSYNC" )
_S(020000,	"O_ASYNC" )
_S(040000,	"O_DIRECT" )
_S(0200000,	"O_DIRECTORY" )
_S(0400000,	"O_NOFOLLOW" )
_S(01000000,	"O_NOATIME" )
_S(02000000,	"O_CLOEXEC")
_S(04000000,	"__O_SYNC")
_S(010000000,	"O_PATH")
_S(020000000,	"__O_TMPFILE")

