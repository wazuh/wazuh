/* persontab.h --
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
 * Location: include/uapi/linux/personality.h
 */

_S(0x0000, "PER_LINUX")
_S(0x0000 | ADDR_LIMIT_32BIT, "PER_LINUX_32BIT")
_S(0x0001 | STICKY_TIMEOUTS | MMAP_PAGE_ZERO, "PER_SVR4")
_S(0x0002 | STICKY_TIMEOUTS | SHORT_INODE, "PER_SVR3")
_S(0x0003 | STICKY_TIMEOUTS | WHOLE_SECONDS | SHORT_INODE, "PER_SCOSVR3")
_S(0x0003 | STICKY_TIMEOUTS | WHOLE_SECONDS, "PER_OSR5")
_S(0x0004 | STICKY_TIMEOUTS | SHORT_INODE, "PER_WYSEV386")
_S(0x0005 | STICKY_TIMEOUTS, "PER_ISCR4")
_S(0x0006, "PER_BSD")
_S(0x0006 | STICKY_TIMEOUTS, "PER_SUNOS")
_S(0x0007 | STICKY_TIMEOUTS | SHORT_INODE, "PER_XENIX")
_S(0x0008, "PER_LINUX32")
_S(0x0008 | ADDR_LIMIT_3GB, "PER_LINUX32_3GB")
_S(0x0009 | STICKY_TIMEOUTS, "PER_IRIX32")
_S(0x000a | STICKY_TIMEOUTS, "PER_IRIXN32")
_S(0x000b | STICKY_TIMEOUTS, "PER_IRIX64")
_S(0x000c, "PER_RISCOS")
_S(0x000d | STICKY_TIMEOUTS, "PER_SOLARIS")
_S(0x000e | STICKY_TIMEOUTS | MMAP_PAGE_ZERO, "PER_UW7")
_S(0x000f, "PER_OSF4")
_S(0x0010, "PER_HPUX")

