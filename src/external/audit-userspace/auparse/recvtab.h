/* recvtab.h --
 * Copyright 2012-14 Red Hat Inc., Durham, North Carolina.
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
 * Location: include/linux/socket.h
 */

_S(0x00000001,    "MSG_OOB")
_S(0x00000002,    "MSG_PEEK")
_S(0x00000004,    "MSG_DONTROUTE")
_S(0x00000008,    "MSG_CTRUNC")
_S(0x00000010,    "MSG_PROXY")
_S(0x00000020,    "MSG_TRUNC")
_S(0x00000040,    "MSG_DONTWAIT")
_S(0x00000080,    "MSG_EOR")
_S(0x00000100,    "MSG_WAITALL")
_S(0x00000200,    "MSG_FIN")
_S(0x00000400,    "MSG_SYN")
_S(0x00000800,    "MSG_CONFIRM")
_S(0x00001000,    "MSG_RST")
_S(0x00002000,    "MSG_ERRQUEUE")
_S(0x00004000,    "MSG_NOSIGNAL")
_S(0x00008000,    "MSG_MORE")
_S(0x00010000,    "MSG_WAITFORONE")
_S(0x00020000,    "MSG_SENDPAGE_NOTLAST")
_S(0x00040000,    "MSG_BATCH")
_S(0x20000000,    "MSG_FASTOPEN")
_S(0x40000000,    "MSG_CMSG_CLOEXEC")
_S(0x80000000,    "MSG_CMSG_COMPAT")

