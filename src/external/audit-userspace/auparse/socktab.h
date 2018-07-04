/* socktab.h --
 * Copyright 2007,2011-13 Red Hat Inc., Durham, North Carolina.
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
 * Location: include/uapi/linux/net.h
 */

_S(SYS_SOCKET,		"socket"	)
_S(SYS_BIND,		"bind"		)
_S(SYS_CONNECT,		"connect"	)
_S(SYS_LISTEN,		"listen"	)
_S(SYS_ACCEPT,		"accept"	)
_S(SYS_GETSOCKNAME,	"getsockname"	)
_S(SYS_GETPEERNAME,	"getpeername"	)
_S(SYS_SOCKETPAIR,	"socketpair"	)
_S(SYS_SEND,		"send"		)
_S(SYS_RECV,		"recv"		)
_S(SYS_SENDTO,		"sendto"	)
_S(SYS_RECVFROM,	"recvfrom"	)
_S(SYS_SHUTDOWN,	"shutdown"	)
_S(SYS_SETSOCKOPT,	"setsockopt"	)
_S(SYS_GETSOCKOPT,	"getsockopt"	)
_S(SYS_SENDMSG,		"sendmsg"	)
_S(SYS_RECVMSG,		"recvmsg"	)
_S(SYS_ACCEPT4,		"accept4"	)
_S(19,			"recvmmsg"	)
_S(20,			"sendmmsg"	)

