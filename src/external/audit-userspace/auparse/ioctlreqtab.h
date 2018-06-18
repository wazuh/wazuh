/* ioctlreqtab.h --
 * Copyright 2014 Red Hat Inc., Durham, North Carolina.
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
 *
 * 	This list is not comprehensive. Its just some cherry picked ioctls.
 *      include/uapi/linux/kd.h
 *	include/uapi/linux/cdrom.h
 *	include/uapi/asm-generic/ioctls.h
 *	include/uapi/drm/drm.h
 */

_S(0x4B3A,	"KDSETMODE"	)
_S(0x4B3B,	"KDGETMODE"	)

_S(0x5309,	"CDROMEJECT"	)
_S(0x530F,	"CDROMEJECT_SW"	)
_S(0x5311,	"CDROM_GET_UPC"	)
_S(0x5316,	"CDROMSEEK"	)

_S(0x5401,	"TCGETS"	)
_S(0x5402,	"TCSETS"	)
_S(0x5403,	"TCSETSW"	)
_S(0x5404,	"TCSETSF"	)
_S(0x5409,	"TCSBRK"	)
_S(0x540B,	"TCFLSH"	)
_S(0x540E,	"TIOCSCTTY"	)
_S(0x540F,	"TIOCGPGRP"	)
_S(0x5410,	"TIOCSPGRP"	)
_S(0x5413,	"TIOCGWINSZ"	)
_S(0x5414,	"TIOCSWINSZ"	)
_S(0x541B,	"TIOCINQ"	)
_S(0x5421,	"FIONBIO"	)
_S(0x5422,	"TIOCNOTTY"	)
_S(0x8901,	"FIOSETOWN"	)
_S(0x8903,	"FIOGETOWN"	)
_S(0x8910,	"SIOCGIFNAME"	)
_S(0x8927,	"SIOCGIFHWADDR"	)
_S(0x8933,	"SIOCGIFINDEX"	)
_S(0x89a2,	"SIOCBRADDIF"	)
_S(0x40045431,	"TIOCSPTLCK"	) // Need a better fix for these
_S(0x80045430,	"TIOCGPTN"	)
_S(0x80045431,	"TIOCSPTLCK"	)

_S(0xC01C64A3,	"DRM_IOCTL_MODE_CURSOR"	)
_S(0xC01864B0,	"DRM_IOCTL_MODE_PAGE_FLIP"	)
_S(0xC01864B1,	"DRM_IOCTL_MODE_DIRTYFB"	)

