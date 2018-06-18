/* seccomptab.h --
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
 * Location: include/uapi/linux/seccomp.h
 */


_S(0x00000000U,	"kill"	)
_S(0x00030000U,	"trap"	)
_S(0x00050000U,	"errno"	)
_S(0x7ff00000U,	"trace"	)
_S(0x7ffc0000U,	"log"	)
_S(0x7fff0000U,	"allow"	)

