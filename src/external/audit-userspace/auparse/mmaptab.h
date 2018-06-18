/* mmaptab.h --
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
 * Location: include/uapi/asm-generic/mman.h  >0x100
 *           include/uapi/asm-generic/mman-common.h < 0x100
 */

_S(0x00001, "MAP_SHARED"	)
_S(0x00002, "MAP_PRIVATE"	)
_S(0x00010, "MAP_FIXED"		)
_S(0x00020, "MAP_ANONYMOUS"	)
_S(0x00040, "MAP_32BIT"		)
_S(0x00100, "MAP_GROWSDOWN"	)
_S(0x00800, "MAP_DENYWRITE"	)
_S(0x01000, "MAP_EXECUTABLE"	)
_S(0x02000, "MAP_LOCKED"	)
_S(0x04000, "MAP_NORESERVE"	)
_S(0x08000, "MAP_POPULATE"	)
_S(0x10000, "MAP_NONBLOCK"	)
_S(0x20000, "MAP_STACK"		)
_S(0x40000, "MAP_HUGETLB"	)

