/* machine.h --
 * Copyright 2005,2006,2009,2012,2013 Red Hat Inc., Durham, North Carolina.
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
 */

_S(MACH_X86,     "i386"   )
_S(MACH_X86,     "i486"   )
_S(MACH_X86,     "i586"   )
_S(MACH_X86,     "i686"   )
_S(MACH_86_64,   "x86_64" )
_S(MACH_IA64,    "ia64"   )
_S(MACH_PPC64,   "ppc64"  )
_S(MACH_PPC64LE, "ppc64le")
_S(MACH_PPC,     "ppc"    )
_S(MACH_S390X,   "s390x"  )
_S(MACH_S390,    "s390"   )
#ifdef WITH_ALPHA
_S(MACH_ALPHA,   "alpha"  )
#endif
#ifdef WITH_ARM
_S(MACH_ARM,   "armeb"  )
_S(MACH_ARM,   "arm"  )
_S(MACH_ARM,   "armv5tejl")
_S(MACH_ARM,   "armv5tel")
_S(MACH_ARM,   "armv6l")
_S(MACH_ARM,   "armv7l")
#endif
#ifdef WITH_AARCH64
_S(MACH_AARCH64,   "aarch64"  )
#endif
