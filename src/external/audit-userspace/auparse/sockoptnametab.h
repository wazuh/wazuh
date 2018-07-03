/* sockoptnametab.h --
 * Copyright 2013-16 Red Hat Inc., Durham, North Carolina.
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
 * File: include/uapi/asm-generic/socket.h
 */


_S(1, "SO_DEBUG")
_S(2, "SO_REUSEADDR")
_S(3, "SO_TYPE")
_S(4, "SO_ERROR")
_S(5, "SO_DONTROUTE")
_S(6, "SO_BROADCAST")
_S(7, "SO_SNDBUF")
_S(8, "SO_RCVBUF")
_S(9, "SO_KEEPALIVE")
_S(10, "SO_OOBINLINE")
_S(11, "SO_NO_CHECK")
_S(12, "SO_PRIORITY")
_S(13, "SO_LINGER")
_S(14, "SO_BSDCOMPAT")
_S(15, "SO_REUSEPORT")
_S(16, "SO_PASSCRED")
_S(17, "SO_PEERCRED")
_S(18, "SO_RCVLOWAT")
_S(19, "SO_SNDLOWAT")
_S(20, "SO_RCVTIMEO")
_S(21, "SO_SNDTIMEO")
_S(22, "SO_SECURITY_AUTHENTICATION")
_S(23, "SO_SECURITY_ENCRYPTION_TRANSPORT")
_S(24, "SO_SECURITY_ENCRYPTION_NETWORK")
_S(25, "SO_BINDTODEVICE")
_S(26, "SO_ATTACH_FILTER")
_S(27, "SO_DETACH_FILTER")
_S(28, "SO_PEERNAME")
_S(29, "SO_TIMESTAMP")
_S(30, "SO_ACCEPTCONN")
_S(31, "SO_PEERSEC")
_S(32, "SO_SNDBUFFORCE")
_S(33, "SO_RCVBUFFORCE")
_S(34, "SO_PASSSEC")
_S(35, "SO_TIMESTAMPNS")
_S(36, "SO_MARK")
_S(37, "SO_TIMESTAMPING")
_S(38, "SO_PROTOCOL")
_S(39, "SO_DOMAIN")
_S(40, "SO_RXQ_OVFL")
_S(41, "SO_WIFI_STATUS")
_S(42, "SO_PEEK_OFF")
_S(43, "SO_NOFCS")
_S(44, "SO_LOCK_FILTER")
_S(45, "SO_SELECT_ERR_QUEUE")
_S(46, "SO_BUSY_POLL")
_S(47, "SO_MAX_PACING_RATE")
_S(48, "SO_BPF_EXTENSIONS")
_S(49, "SO_INCOMING_CPU")
_S(50, "SO_ATTACH_BPF")
_S(51, "SO_ATTACH_REUSEPORT_CBPF")
_S(52, "SO_ATTACH_REUSEPORT_EBPF")
_S(53, "SO_CNX_ADVICE")
_S(54, "SCM_TIMESTAMPING_OPT_STATS")
_S(55, "SO_MEMINFO")
_S(56, "SO_INCOMING_NAPI_ID")
_S(57, "SO_COOKIE")
_S(58, "SCM_TIMESTAMPING_PKTINFO")
_S(59, "SO_PEERGROUPS")
_S(60, "SO_ZEROCOPY")

// PPC has these different
_S(116, "SO_RCVLOWAT")
_S(117, "SO_SNDLOWAT")
_S(118, "SO_RCVTIMEO")
_S(119, "SO_SNDTIMEO")
_S(120, "SO_PASSCRED")
_S(121, "SO_PEERCRED")


