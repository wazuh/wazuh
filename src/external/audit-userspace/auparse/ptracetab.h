/* ptracetab.h --
 * Copyright 2012-14,16 Red Hat Inc., Durham, North Carolina.
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
 * Location: include/uapi/linux/ptrace.h
 *           ./arch/x86/include/uapi/asm/ptrace-abi.h
 */

_S(0,		"PTRACE_TRACEME"	)
_S(1,		"PTRACE_PEEKTEXT"	)
_S(2,		"PTRACE_PEEKDATA"	)
_S(3,		"PTRACE_PEEKUSER"	)
_S(4,		"PTRACE_POKETEXT"	)
_S(5,		"PTRACE_POKEDATA"	)
_S(6,		"PTRACE_POKEUSER"	)
_S(7,		"PTRACE_CONT"		)
_S(8,		"PTRACE_KILL"		)
_S(9,		"PTRACE_SINGLESTEP"	)
_S(12,		"PTRACE_GETREGS"	)
_S(13,		"PTRACE_SETREGS"	)
_S(14,		"PTRACE_GETFPREGS"	)
_S(15,		"PTRACE_SETFPREGS"	)
_S(16,		"PTRACE_ATTACH"		)
_S(17,		"PTRACE_DETACH"		)
_S(18,		"PTRACE_GETFPXREGS"	)
_S(19,		"PTRACE_SETFPXREGS"	)
_S(24,		"PTRACE_SYSCALL"	)
_S(25,		"PTRACE_GET_THREAD_AREA")
_S(26,		"PTRACE_SET_THREAD_AREA")
_S(30,		"PTRACE_ARCH_PRCTL"	)
_S(31,		"PTRACE_SYSEMU"		)
_S(32,		"PTRACE_SYSEMU_SINGLESTEP")
_S(33,		"PTRACE_SINGLEBLOCK"	)
_S(0x4200,	"PTRACE_SETOPTIONS"	)
_S(0x4201,	"PTRACE_GETEVENTMSG"	)
_S(0x4202,	"PTRACE_GETSIGINFO"	)
_S(0x4203,	"PTRACE_SETSIGINFO"	)
_S(0x4204,	"PTRACE_GETREGSET"	)
_S(0x4205,	"PTRACE_SETREGSET"	)
_S(0x4206,	"PTRACE_SEIZE"		)
_S(0x4207,	"PTRACE_INTERRUPT"	)
_S(0x4208,	"PTRACE_LISTEN"		)
_S(0x4209,	"PTRACE_PEEKSIGINFO"	)
_S(0x420a,	"PTRACE_GETSIGMASK"	)
_S(0x420b,	"PTRACE_SETSIGMASK"	)
_S(0x420c,	"PTRACE_SECCOMP_GET_FILTER"	)

