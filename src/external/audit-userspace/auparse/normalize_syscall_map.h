/*
 * normalize_syscall_map.h
 * Copyright (c) 2016-17 Red Hat Inc., Durham, North Carolina.
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
 *   Steve Grubb <sgrubb@redhat.com>
 */
#include "normalize-internal.h"

_S(NORM_FILE_STAT, "access")
_S(NORM_FILE_STAT, "faccessat")
_S(NORM_FILE_CHPERM, "chmod")
_S(NORM_FILE_CHPERM, "fchmod")
_S(NORM_FILE_CHPERM, "fchmodat")
_S(NORM_FILE_CHOWN, "chown")
_S(NORM_FILE_CHOWN, "fchown")
_S(NORM_FILE_CHOWN, "fchownat")
_S(NORM_FILE_CHOWN, "lchown")
_S(NORM_FILE_LDMOD, "finit_module")
_S(NORM_FILE_LDMOD, "init_module")
_S(NORM_FILE_UNLDMOD, "delete_module")
_S(NORM_FILE_CHATTR, "setxattr")
_S(NORM_FILE_CHATTR, "fsetxattr")
_S(NORM_FILE_CHATTR, "lsetxattr")
_S(NORM_FILE_DIR, "mkdir")
_S(NORM_FILE_DIR, "mkdirat")
_S(NORM_FILE_MOUNT, "mount")
_S(NORM_FILE_STAT, "newfstatat")
_S(NORM_FILE_STAT, "stat")
_S(NORM_FILE_STAT, "fstat")
_S(NORM_FILE_STAT, "lstat")
_S(NORM_FILE_STAT, "stat64")
_S(NORM_FILE_SYS_STAT, "statfs")
_S(NORM_FILE_SYS_STAT, "fstatfs")
_S(NORM_FILE, "creat")
_S(NORM_FILE, "fallocate")
_S(NORM_FILE, "truncate")
_S(NORM_FILE, "ftruncate")
_S(NORM_FILE, "open")
_S(NORM_FILE, "openat")
_S(NORM_FILE, "readlink")
_S(NORM_FILE, "readlinkat")
_S(NORM_FILE_CHATTR, "removexattr")
_S(NORM_FILE_CHATTR, "fremovexattr")
_S(NORM_FILE_CHATTR, "lremovexattr")
_S(NORM_FILE_RENAME, "rename")
_S(NORM_FILE_RENAME, "renameat")
_S(NORM_FILE_RENAME, "renameat2")
_S(NORM_FILE_DEL, "rmdir")
_S(NORM_FILE_LNK, "symlink")
_S(NORM_FILE_LNK, "symlinkat")
_S(NORM_FILE_UMNT, "umount")
_S(NORM_FILE_UMNT, "umount2")
_S(NORM_FILE_DEL, "unlink")
_S(NORM_FILE_DEL, "unlinkat")
_S(NORM_FILE_TIME, "utime")
_S(NORM_FILE_TIME, "utimes")
_S(NORM_FILE_TIME, "futimesat")
_S(NORM_FILE_TIME, "utimensat")
_S(NORM_EXEC, "execve")
_S(NORM_EXEC, "execveat")
_S(NORM_SOCKET_ACCEPT, "accept")
_S(NORM_SOCKET_ACCEPT, "accept4")
_S(NORM_SOCKET_BIND, "bind")
_S(NORM_SOCKET_CONN, "connect")
_S(NORM_SOCKET_RECV, "recvfrom")
_S(NORM_SOCKET_RECV, "recvmsg")
_S(NORM_SOCKET_SEND, "sendmsg")
_S(NORM_SOCKET_SEND, "sendto")
_S(NORM_PID, "kill")
_S(NORM_PID, "tkill")
_S(NORM_PID, "tgkill")
_S(NORM_UID, "setuid")
_S(NORM_UID, "seteuid")
_S(NORM_UID, "setfsuid")
_S(NORM_UID, "setreuid")
_S(NORM_UID, "setresuid")
_S(NORM_GID, "setgid")
_S(NORM_GID, "setegid")
_S(NORM_GID, "setfsgid")
_S(NORM_GID, "setregid")
_S(NORM_GID, "setresgid")
_S(NORM_SYSTEM_TIME, "settimeofday")
_S(NORM_SYSTEM_TIME, "clock_settime")
_S(NORM_SYSTEM_TIME, "stime")
_S(NORM_SYSTEM_TIME, "adjtimex")
_S(NORM_MAKE_DEV, "mknod")
_S(NORM_MAKE_DEV, "mknodat")
_S(NORM_SYSTEM_NAME, "sethostname")
_S(NORM_SYSTEM_NAME, "setdomainname")
_S(NORM_SYSTEM_MEMORY, "mmap")
_S(NORM_SYSTEM_MEMORY, "brk")
_S(NORM_SCHEDULER, "sched_setparam")
_S(NORM_SCHEDULER, "sched_setscheduler")
_S(NORM_SCHEDULER, "sched_setattr")

