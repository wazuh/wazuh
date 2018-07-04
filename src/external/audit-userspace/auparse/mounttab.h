/* mounttab.h --
 * Copyright 2012-13 Red Hat Inc., Durham, North Carolina.
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
 * Location: include/uapi/linux/fs.h
 * NOTE: When updating this table, update interpret.c:print_mount()
 */

_S(MS_RDONLY, "MS_RDONLY")
_S(MS_NOSUID, "MS_NOSUID")
_S(MS_NODEV, "MS_NODEV" )
_S(MS_NOEXEC, "MS_NOEXEC")
_S(MS_SYNCHRONOUS, "MS_SYNCHRONOUS")
_S(MS_REMOUNT, "MS_REMOUNT")
_S(MS_MANDLOCK, "MS_MANDLOCK")
_S(MS_DIRSYNC, "MS_DIRSYNC")
_S(MS_NOATIME, "MS_NOATIME")
_S(MS_NODIRATIME, "MS_NODIRATIME")
_S(MS_BIND, "MS_BIND")
_S(MS_MOVE, "MS_MOVE")
_S(MS_REC, "MS_REC")
_S(MS_SILENT, "MS_SILENT")
_S(MS_POSIXACL, "MS_POSIXACL")
_S(MS_UNBINDABLE, "MS_UNBINDABLE")
_S(MS_PRIVATE, "MS_PRIVATE")
_S(MS_SLAVE, "MS_SLAVE")
_S(MS_SHARED, "MS_SHARED")
_S(MS_RELATIME, "MS_RELATIME")
_S(MS_KERNMOUNT, "MS_KERNMOUNT")
_S(MS_I_VERSION, "MS_I_VERSION")
_S((1<<24), "MS_STRICTATIME")
_S((1<<27), "MS_SNAP_STABLE")
_S((1<<28), "MS_NOSEC")
_S((1<<29), "MS_BORN")
_S(MS_ACTIVE, "MS_ACTIVE")
_S(MS_NOUSER, "MS_NOUSER")

