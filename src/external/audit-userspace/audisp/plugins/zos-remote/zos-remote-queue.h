/***************************************************************************
 *   Copyright (C) 2007 International Business Machines  Corp.             *
 *   All Rights Reserved.                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                         *
 * Authors:                                                                *
 *   Klaus Heinrich Kiwi <klausk@br.ibm.com>                               *
 *   based on code by Steve Grubb <sgrubb@redhat.com>                      *
 ***************************************************************************/

#ifndef _ZOS_REMOTE_QUEUE_H
#define _ZOS_REMOTE_QUEUE_H

#include <lber.h>

int init_queue(unsigned int size);
void enqueue(BerElement *);
BerElement *dequeue(void);
void nudge_queue(void);
void increase_queue_depth(unsigned int size);
void destroy_queue(void);

#endif       /* _ZOS_REMOTE_QUEUE_H */

