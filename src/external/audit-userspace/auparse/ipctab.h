/* ipctab.h --
 * Copyright 2007,2012-13 Red Hat Inc., Durham, North Carolina.
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
 * Location: include/uapi/linux/ipc.h
 */


_S(SEMOP,	"semop"		)
_S(SEMGET,	"semget"	)
_S(SEMCTL,	"semctl"	)
_S(4,		"semtimedop"	)
_S(MSGSND,	"msgsnd"	)
_S(MSGRCV,	"msgrcv"	)
_S(MSGGET,	"msgget"	)
_S(MSGCTL,	"msgctl"	)
_S(SHMAT,	"shmat"		)
_S(SHMDT,	"shmdt"		)
_S(SHMGET,	"shmget"	)
_S(SHMCTL,	"shmctl"	)

