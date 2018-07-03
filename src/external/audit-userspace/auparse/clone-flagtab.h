/* clone-flagtab.h --
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
 * Location: include/uapi/linux/sched.h
 */

_S(0x00000100,	"CLONE_VM" )
_S(0x00000200,	"CLONE_FS" )
_S(0x00000400,	"CLONE_FILES" )
_S(0x00000800,	"CLONE_SIGHAND" )
_S(0x00002000,	"CLONE_PTRACE" )
_S(0x00004000,	"CLONE_VFORK" )
_S(0x00008000,	"CLONE_PARENT" )
_S(0x00010000,	"CLONE_THREAD" )
_S(0x00020000,	"CLONE_NEWNS" )
_S(0x00040000,	"CLONE_SYSVSEM" )
_S(0x00080000,	"CLONE_SETTLS" )
_S(0x00100000,	"CLONE_PARENT_SETTID" )
_S(0x00200000,	"CLONE_CHILD_CLEARTID" )
_S(0x00400000,	"CLONE_DETACHED" )
_S(0x00800000,	"CLONE_UNTRACED" )
_S(0x01000000,	"CLONE_CHILD_SETTID" )
_S(0x02000000,	"CLONE_STOPPED" )
_S(0x04000000,	"CLONE_NEWUTS" )
_S(0x08000000,	"CLONE_NEWIPC" )
_S(0x10000000,	"CLONE_NEWUSER" )
_S(0x20000000,	"CLONE_NEWPID" )
_S(0x40000000,	"CLONE_NEWNET" )
_S(0x80000000,	"CLONE_IO" )

