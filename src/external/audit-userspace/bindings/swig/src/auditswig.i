/* Author: Dan Walsh
 *
 * Copyright (C) 2005,2006,2009 Red Hat
 * 
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


%module audit
%{
        #include "../lib/libaudit.h"
%}

#if defined(SWIGPYTHON)
%exception audit_open {
  $action
  if (result < 0) {
    PyErr_SetFromErrno(PyExc_OSError);
    return NULL;
  }
}
#endif

%define __signed__
signed
%enddef
#define __attribute(X) /*nothing*/
typedef unsigned __u32;
typedef unsigned uid_t;
%include "/usr/include/linux/audit.h"
#define __extension__ /*nothing*/
%include "/usr/include/stdint.h"
%include "../lib/libaudit.h"

