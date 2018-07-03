/* normalize.c --
 * Copyright 2016-18 Red Hat Inc., Durham, North Carolina.
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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include "libaudit.h"
#include "auparse.h"
#include "internal.h"
#include "normalize-llist.h"
#include "normalize-internal.h"
#include "gen_tables.h"
#include "normalize_record_maps.h"
#include "normalize_syscall_maps.h"
#include "normalize_obj_kind_maps.h"
#include "normalize_evtypetabs.h"


/*
 * Field accessors. x is the new value, y is the variable
 * Layout is: 0xFFFF FFFF  where first is record and second is field
 * Both record and field are 0 based. Simple records are always 0. Compound
 * records start at 0 and go up.
 */
#define UNSET 0xFFFF
#define get_record(y) ((y >> 16) & 0x0000FFFF)
#define set_record(y, x) (((x & 0x0000FFFF) << 16) | (y & 0x0000FFFF))
#define get_field(y) (y & 0x0000FFFF)
#define set_field(y, x) ((y & 0xFFFF0000) | (x & 0x0000FFFF))
#define is_unset(y) (get_record(y) == UNSET)
#define D au->norm_data

static int syscall_success;

void init_normalizer(normalize_data *d)
{
	d->evkind = NULL;
	d->session = set_record(0, UNSET);
	d->actor.primary = set_record(0, UNSET);
	d->actor.secondary = set_record(0, UNSET);
	d->actor.what = NULL;
	cllist_create(&d->actor.attr, NULL);
	d->action = NULL;
	d->thing.primary = set_record(0, UNSET);
	d->thing.secondary = set_record(0, UNSET);
	d->thing.two = set_record(0, UNSET);
	cllist_create(&d->thing.attr, NULL);
	d->thing.what = NORM_WHAT_UNKNOWN;
	d->results = set_record(0, UNSET);
	d->how = NULL;
	d->opt = NORM_OPT_ALL;
	d->key = set_record(0, UNSET);
	syscall_success = -1;
}

void clear_normalizer(normalize_data *d)
{
	d->evkind = NULL;
	d->session = set_record(0, UNSET);
	d->actor.primary = set_record(0, UNSET);
	d->actor.secondary = set_record(0, UNSET);
	free((void *)d->actor.what);
	d->actor.what = NULL;
	cllist_clear(&d->actor.attr);
	free((void *)d->action);
	d->action = NULL;
	d->thing.primary = set_record(0, UNSET);
	d->thing.secondary = set_record(0, UNSET);
	d->thing.two = set_record(0, UNSET);
	cllist_clear(&d->thing.attr);
	d->thing.what = NORM_WHAT_UNKNOWN;
	d->results = set_record(0, UNSET);
	free((void *)d->how);
	d->how = NULL;
	d->opt = NORM_OPT_ALL;
	d->key = set_record(0, UNSET);
	syscall_success = -1;
}

static unsigned int set_subject_what(auparse_state_t *au)
{
	int uid = NORM_ACCT_UNSET - 1;
	int ftype = auparse_get_field_type(au);
	if (ftype == AUPARSE_TYPE_UID)
		uid = auparse_get_field_int(au);
	else {
		const char *n = auparse_get_field_name(au);
		if (n && strcmp(n, "acct") == 0) {
			const char *acct = auparse_interpret_field(au);
			if (acct) {
				// FIXME: Make this a LRU item
				struct passwd *pw = getpwnam(acct);
				if (pw) {
					uid = pw->pw_uid;
					goto check;
				}
			}
		}
		return 1;
	}

check:
	if (uid == NORM_ACCT_PRIV)
		D.actor.what = strdup("priviliged-acct");
	else if ((unsigned)uid == NORM_ACCT_UNSET)
		D.actor.what = strdup("unset-acct");
	else if (uid < NORM_ACCT_MAX_SYS)
		D.actor.what = strdup("service-acct");
	else if (uid < NORM_ACCT_MAX_USER)
		D.actor.what = strdup("user-acct");
	else
		D.actor.what = strdup("unknown-acct");
	return 0;
}

static unsigned int set_prime_subject(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	if (auparse_find_field(au, str)) {
		D.actor.primary = set_record(0, rnum);
		D.actor.primary = set_field(D.actor.primary,
				auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static unsigned int set_secondary_subject(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	if (auparse_find_field(au, str)) {
		D.actor.secondary = set_record(0, rnum);
		D.actor.secondary = set_field(D.actor.secondary,
				auparse_get_field_num(au));
		return set_subject_what(au);
	}
	return 1;
}

static unsigned int add_subj_attr(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	value_t attr;

	if ((auparse_find_field(au, str))) {
		attr = set_record(0, rnum);
		attr = set_field(attr, auparse_get_field_num(au));
		cllist_append(&D.actor.attr, attr, NULL);
		return 0;
	} else
		auparse_goto_record_num(au, rnum);

	return 1;
}

static unsigned int set_prime_object(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	if (auparse_find_field(au, str)) {
		D.thing.primary = set_record(0, rnum);
		D.thing.primary = set_field(D.thing.primary,
			auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static unsigned int set_prime_object2(auparse_state_t *au, const char *str,
	unsigned int adjust)
{
	unsigned int rnum = 2 + adjust;

	auparse_goto_record_num(au, rnum);
	auparse_first_field(au);

	if (auparse_find_field(au, str)) {
		D.thing.two = set_record(0, rnum);
		D.thing.two = set_field(D.thing.two,
			auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static unsigned int add_obj_attr(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	value_t attr;

	if ((auparse_find_field(au, str))) {
		attr = set_record(0, rnum);
		attr = set_field(attr, auparse_get_field_num(au));
		cllist_append(&D.thing.attr, attr, NULL);
		return 0;
	} else
		auparse_goto_record_num(au, rnum);
	return 1;
}

static unsigned int add_session(auparse_state_t *au, unsigned int rnum)
{
	if (auparse_find_field(au, "ses")) {
		D.session = set_record(0, rnum);
		D.session = set_field(D.session,
				auparse_get_field_num(au));
		return 0;
	} else
		auparse_first_record(au);
	return 1;
}

static unsigned int set_results(auparse_state_t *au, unsigned int rnum)
{
	if (auparse_find_field(au, "res")) {
		D.results = set_record(0, rnum);
		D.results = set_field(D.results, auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static void syscall_subj_attr(auparse_state_t *au)
{
	unsigned int rnum;

	auparse_first_record(au);
	do {
		rnum = auparse_get_record_num(au);
		if (auparse_get_type(au) == AUDIT_SYSCALL) {
			if (D.opt == NORM_OPT_NO_ATTRS) {
				add_session(au, rnum);
				return;
			}

			add_subj_attr(au, "ppid", rnum);
			add_subj_attr(au, "pid", rnum);
			add_subj_attr(au, "gid", rnum);
			add_subj_attr(au, "euid", rnum);
			add_subj_attr(au, "suid", rnum);
			add_subj_attr(au, "fsuid", rnum);
			add_subj_attr(au, "egid", rnum);
			add_subj_attr(au, "sgid", rnum);
			add_subj_attr(au, "fsgid", rnum);
			add_subj_attr(au, "tty", rnum);
			add_session(au, rnum);
			add_subj_attr(au, "subj", rnum);
			return;
		}
	} while (auparse_next_record(au) == 1);
}

static void collect_perm_obj2(auparse_state_t *au, const char *syscall)
{
	const char *val;

	if (strcmp(syscall, "fchmodat") == 0)
		val = "a2";
	else
		val = "a1";

	auparse_first_record(au);
	if (auparse_find_field(au, val)) {
		D.thing.two = set_record(0, 0);
		D.thing.two = set_field(D.thing.two,
			auparse_get_field_num(au));
	}
}

static void collect_own_obj2(auparse_state_t *au, const char *syscall)
{
	const char *val;

	if (strcmp(syscall, "fchownat") == 0)
		val = "a2";
	else
		val = "a1";

	auparse_first_record(au);
	if (auparse_find_field(au, val)) {
		// if uid is -1, its not being changed, user group
		if (auparse_get_field_int(au) == -1 && errno == 0)
			auparse_next_field(au);
		D.thing.two = set_record(0, 0);
		D.thing.two = set_field(D.thing.two,
			auparse_get_field_num(au));
	}
}

static void collect_id_obj2(auparse_state_t *au, const char *syscall)
{
	unsigned int limit, cnt = 1;;

	if (strcmp(syscall, "setuid") == 0)
		limit = 1;
	else if (strcmp(syscall, "setreuid") == 0)
		limit = 2;
	else if (strcmp(syscall, "setresuid") == 0)
		limit = 3;
	else if (strcmp(syscall, "setgid") == 0)
		limit = 1;
	else if (strcmp(syscall, "setregid") == 0)
		limit = 2;
	else if (strcmp(syscall, "setresgid") == 0)
		limit = 3;
	else
		return; // Shouldn't happen

	auparse_first_record(au);
	if (auparse_find_field(au, "a0")) {
		while (cnt <= limit) {
			const char *str = auparse_interpret_field(au);
			if ((strcmp(str, "unset") == 0) && errno == 0) {
				// Only move it if its safe to
				if (cnt < limit) {
					auparse_next_field(au);
					cnt++;
				}
			} else
				break;
		}
		D.thing.two = set_record(0, 0);
		D.thing.two = set_field(D.thing.two,
			auparse_get_field_num(au));
	}
}

static void collect_path_attrs(auparse_state_t *au)
{
	value_t attr;
	unsigned int rnum = auparse_get_record_num(au);

	auparse_first_field(au);
	if (add_obj_attr(au, "mode", rnum))
		return;	// Failed opens don't have anything else

	// All the rest of the fields matter
	while ((auparse_next_field(au))) {
		attr = set_record(0, rnum);
		attr = set_field(attr, auparse_get_field_num(au));
		cllist_append(&D.thing.attr, attr, NULL);
	}
}

static void collect_cwd_attrs(auparse_state_t *au)
{
	unsigned int rnum = auparse_get_record_num(au);
	add_obj_attr(au, "cwd", rnum);
}

static void collect_sockaddr_attrs(auparse_state_t *au)
{
	unsigned int rnum = auparse_get_record_num(au);
	add_obj_attr(au, "saddr", rnum);
}

static void simple_file_attr(auparse_state_t *au)
{
	int parent = 0;

	if (D.opt == NORM_OPT_NO_ATTRS)
		return;

	auparse_first_record(au);
	do {
		const char *f;
		int type = auparse_get_type(au);
		switch (type)
		{
			case AUDIT_PATH:
				f = auparse_find_field(au, "nametype");
				if (f && strcmp(f, "PARENT") == 0) {
					if (parent == 0)
					    parent = auparse_get_record_num(au);
					continue;
				}
				// First normal record is collected
				collect_path_attrs(au);
				return;
				break;
			case AUDIT_CWD:
				collect_cwd_attrs(au);
				break;
			case AUDIT_SOCKADDR:
				collect_sockaddr_attrs(au);
				break;
		}
	} while (auparse_next_record(au) == 1);

	// If we get here, path was never collected. Go back and get parent
	if (parent) {
		auparse_goto_record_num(au, parent);
		collect_path_attrs(au);
	}
}

static void set_file_object(auparse_state_t *au, int adjust)
{
	const char *f;
	int parent = 0;
	unsigned int rnum;

	auparse_goto_record_num(au, 2 + adjust);
	auparse_first_field(au);

	// Now double check that we picked the right one.
	do {
		f = auparse_find_field(au, "nametype");
		if (f) {
			if (strcmp(f, "PARENT"))
				break;
			if (parent == 0)
				parent = auparse_get_record_num(au);
		}
	} while (f && auparse_next_record(au) == 1);

	// Sometimes we only have the parent (failed open at dir permission)
	if (f == NULL) {
		if (parent == 0)
			return;

		auparse_goto_record_num(au, parent);
		auparse_first_field(au);
		rnum = parent;
	} else
		rnum = auparse_get_record_num(au);

	if (auparse_get_type(au) == AUDIT_PATH) {
		auparse_first_field(au);

		// Object
		set_prime_object(au, "name", rnum);

		f = auparse_find_field(au, "inode");
		if (f) {
			D.thing.secondary = set_record(0, rnum);
			D.thing.secondary = set_field(D.thing.secondary,
						auparse_get_field_num(au));
		}
		f = auparse_find_field(au, "mode");
		if (f) {
			unsigned int mode;
			errno = 0;
			mode = strtoul(f, NULL, 8);
			if (errno == 0) {
				if (S_ISREG(mode))
					D.thing.what = NORM_WHAT_FILE;
				else if (S_ISDIR(mode))
					D.thing.what = NORM_WHAT_DIRECTORY;
				else if (S_ISCHR(mode))
					D.thing.what = NORM_WHAT_CHAR_DEV;
				else if (S_ISBLK(mode))
					D.thing.what = NORM_WHAT_BLOCK_DEV;
				else if (S_ISFIFO(mode))
					D.thing.what = NORM_WHAT_FIFO;
				else if (S_ISLNK(mode))
					D.thing.what = NORM_WHAT_LINK;
				else if (S_ISSOCK(mode))
					D.thing.what = NORM_WHAT_SOCKET;
			}
		}
	}
}

static void set_socket_object(auparse_state_t *au)
{
	auparse_goto_record_num(au, 1);
	auparse_first_field(au);
	set_prime_object(au, "saddr", 1);
}

/* This is only called processing syscall records */
static int set_program_obj(auparse_state_t *au)
{
	auparse_first_record(au);
	if (auparse_find_field(au, "exe")) {
		const char *exe = auparse_interpret_field(au);
		if ((strncmp(exe, "/usr/bin/python", 15) == 0) ||
		    (strncmp(exe, "/usr/bin/sh", 11) == 0) ||
		    (strncmp(exe, "/usr/bin/bash", 13) == 0) ||
		    (strncmp(exe, "/usr/bin/perl", 13) == 0)) {
			// comm should be the previous field
			int fnum;
			if ((fnum = auparse_get_field_num(au)) > 0)
				auparse_goto_field_num(au, fnum - 1);
			else
				auparse_first_record(au);
			auparse_find_field(au, "comm");
		}

		D.thing.primary = set_record(0,
				auparse_get_record_num(au));
		D.thing.primary = set_field(D.thing.primary,
				auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

/*
 * This function is supposed to come up with the action and object for the
 * syscalls.
 */
static int normalize_syscall(auparse_state_t *au, const char *syscall)
{
	int rc, tmp_objkind, objtype = NORM_UNKNOWN, ttype = 0, offset = 0;
	const char *act = NULL, *f;

	// cycle through all records and see what we have
	tmp_objkind = objtype;
	rc = auparse_first_record(au);
	while (rc == 1) {
		ttype = auparse_get_type(au);

		if (ttype == AUDIT_AVC) {
			// We want to go ahead with syscall to get objects
			tmp_objkind = NORM_MAC;
			break;
		} else if (ttype == AUDIT_SELINUX_ERR) {
			objtype = NORM_MAC_ERR;
			break;
		} else if (ttype == AUDIT_NETFILTER_CFG) {
			objtype = NORM_IPTABLES;
			break;
		} else if (ttype == AUDIT_ANOM_PROMISCUOUS) {
			objtype = NORM_PROMISCUOUS;
			break;
		} else if (ttype == AUDIT_KERN_MODULE) {
			objtype = NORM_FILE_LDMOD;
			break;
		} else if (ttype == AUDIT_MAC_POLICY_LOAD) {
			objtype = NORM_MAC_LOAD;
			break;
		} else if (ttype == AUDIT_MAC_STATUS) {
			objtype = NORM_MAC_ENFORCE;
			break;
		} else if (ttype == AUDIT_MAC_CONFIG_CHANGE) {
			objtype = NORM_MAC_CONFIG;
			break;
		} else if (ttype == AUDIT_FANOTIFY) {
			tmp_objkind = NORM_AV;
			break;
		}
		rc = auparse_next_record(au);
	}

	// lookup system call - it can be NULL if interpret_field failed. In
	// that case, the s2i call will fail and leave objtype untouched
	if (objtype == NORM_UNKNOWN)
		normalize_syscall_map_s2i(syscall, &objtype);

	switch (objtype)
	{
		case NORM_FILE:
			act = "opened-file";
			set_file_object(au, 0);
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			simple_file_attr(au);
			break;
		case NORM_FILE_CHATTR:
			act = "changed-file-attributes-of";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			if (strcmp(syscall, "fsetxattr") == 0)
				offset = -1;
			set_file_object(au, offset);
			simple_file_attr(au);
			break;
		case NORM_FILE_CHPERM:
			act = "changed-file-permissions-of";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			if (strcmp(syscall, "fchmod") == 0)
				offset = -1;
			collect_perm_obj2(au, syscall);
			set_file_object(au, offset);
			simple_file_attr(au);
			break;
		case NORM_FILE_CHOWN:
			act = "changed-file-ownership-of";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			if (strcmp(syscall, "fchown") == 0)
				offset = -1;
			collect_own_obj2(au, syscall);
			set_file_object(au, offset); // FIXME: fchown has no cwd
			simple_file_attr(au);
			break;
		case NORM_FILE_LDMOD:
			act = "loaded-kernel-module";
			D.thing.what = NORM_WHAT_FILE; 
			auparse_goto_record_num(au, 1);
			set_prime_object(au, "name", 1);// FIXME:is this needed?
			break;
		case NORM_FILE_UNLDMOD:
			act = "unloaded-kernel-module";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			// set_file_object(au, 0);
			// simple_file_attr(au);
			break;
		case NORM_FILE_DIR:
			act = "created-directory";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			set_file_object(au, 1); // New dir is one after
			simple_file_attr(au);
			break;
		case NORM_FILE_MOUNT:
			act = "mounted";
			// this gets overridden
			D.thing.what = NORM_WHAT_FILESYSTEM;
			if (syscall_success == 1)
				set_prime_object2(au, "name", 0);
			//The device is 1 after on success 0 on fail
			set_file_object(au, syscall_success);
			// We call this directly to make sure the right
			// PATH record is used. (There can be 4.)
			collect_path_attrs(au);
			break;
		case NORM_FILE_RENAME:
			act = "renamed";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			set_prime_object2(au, "name", 4);
			set_file_object(au, 2); // Thing renamed is 2 after
			simple_file_attr(au);
			break;
		case NORM_FILE_STAT:
			act = "checked-metadata-of";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case NORM_FILE_SYS_STAT:
			act = "checked-filesystem-metadata-of";
			D.thing.what = NORM_WHAT_FILESYSTEM; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case NORM_FILE_LNK:
			act = "symlinked";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			set_prime_object2(au, "name", 0);
			set_file_object(au, 2);
			simple_file_attr(au);
			break;
		case NORM_FILE_UMNT:
			act = "unmounted";
			D.thing.what = NORM_WHAT_FILESYSTEM; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case NORM_FILE_DEL:
			act = "deleted";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case NORM_FILE_TIME:
			act = "changed-timestamp-of";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case NORM_EXEC:
			act = "executed";
			D.thing.what = NORM_WHAT_FILE; // this gets overridden
			set_file_object(au, 1);
			simple_file_attr(au);
			break;
		case NORM_SOCKET_ACCEPT:
			act = "accepted-connection-from";
			D.thing.what = NORM_WHAT_SOCKET;
			set_socket_object(au);
			break;
		case NORM_SOCKET_BIND:
			act = "bound-socket";
			D.thing.what = NORM_WHAT_SOCKET;
			set_socket_object(au);
			break;
		case NORM_SOCKET_CONN:
			act = "connected-to";
			D.thing.what = NORM_WHAT_SOCKET;
			set_socket_object(au);
			break;
		case NORM_SOCKET_RECV:
			act = "received-from";
			D.thing.what = NORM_WHAT_SOCKET;
			set_socket_object(au);
			break;
		case NORM_SOCKET_SEND:
			act = "sent-to";
			D.thing.what = NORM_WHAT_SOCKET;
			set_socket_object(au);
			break;
		case NORM_PID:
			if (auparse_get_num_records(au) > 2)
				// FIXME: this has implications for object
				act = "killed-list-of-pids";
			else
				act = "killed-pid";
			auparse_goto_record_num(au, 1);
			auparse_first_field(au);
			f = auparse_find_field(au, "saddr");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			D.thing.what = NORM_WHAT_PROCESS;
			break;
		case NORM_MAC_LOAD:
			act = normalize_record_map_i2s(ttype);
			// FIXME: What is the object?
			D.thing.what = NORM_WHAT_MAC_CONFIG;
			break;
		case NORM_MAC_CONFIG:
			act = normalize_record_map_i2s(ttype);
			f = auparse_find_field(au, "bool");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			D.thing.what = NORM_WHAT_MAC_CONFIG;
			break;
		case NORM_MAC_ENFORCE:
			act = normalize_record_map_i2s(ttype);
			f = auparse_find_field(au, "enforcing");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			D.thing.what = NORM_WHAT_MAC_CONFIG;
			break;
		case NORM_MAC_ERR:
			// FIXME: What could the object be?
			act = "caused-mac-policy-error";
			// For now we'll call the obj_kind the system
			D.thing.what = NORM_WHAT_SYSTEM;
			break;
		case NORM_IPTABLES:
			act = "loaded-firewall-rule-to";
			auparse_first_record(au);
			f = auparse_find_field(au, "table");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			D.thing.what = NORM_WHAT_FIREWALL;
			break;
		case NORM_PROMISCUOUS:
			auparse_first_record(au);
			f = auparse_find_field(au, "dev");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			f = auparse_find_field(au, "prom");
			if (f) {
				int i = auparse_get_field_int(au);
				if (i == 0)
					act = "left-promiscuous-mode-on-device";
				else
					act = "entered-promiscuous-mode-on-device";
			}
			D.thing.what = NORM_WHAT_SOCKET;
			break;
		case NORM_UID:
		case NORM_GID:
			act = "changed-identity-of";
			D.thing.what = NORM_WHAT_PROCESS;
			set_program_obj(au);
			if (D.how) {
				free((void *)D.how);
				D.how = strdup(syscall);
			}
			collect_id_obj2(au, syscall);
			break;
		case NORM_SYSTEM_TIME:
			act = "changed-system-time";
			// TODO: can't think of an object for this one
			D.thing.what = NORM_WHAT_SYSTEM;
			break;
		case NORM_MAKE_DEV:
			set_file_object(au, 0);
			simple_file_attr(au);
			if (D.thing.what == NORM_WHAT_CHAR_DEV)
				act = "made-character-device";
			else if (D.thing.what == NORM_WHAT_BLOCK_DEV)
				act = "made-block-device";
			else
				act = "make-device";
			break;
		case NORM_SYSTEM_NAME:
			act = "changed-system-name";
			// TODO: can't think of an object for this one
			D.thing.what = NORM_WHAT_SYSTEM;
			break;
		case NORM_SYSTEM_MEMORY:
			act = "allocated-memory";
			if (syscall_success == 1) {
				// If its not a mmap avc, we can use comm
				act = "allocated-memory-in";
				auparse_first_record(au);
				f = auparse_find_field(au, "comm");
				if (f) {
					D.thing.primary = set_record(0,
						auparse_get_record_num(au));
					D.thing.primary =
						set_field(D.thing.primary,
						auparse_get_field_num(au));
				}
			}
			D.thing.what = NORM_WHAT_MEMORY;
			break;
		case NORM_SCHEDULER:
			act = "adjusted-scheduling-policy-of";
			D.thing.what = NORM_WHAT_PROCESS;
			set_program_obj(au);
			if (D.how) {
				free((void *)D.how);
				D.how = strdup(syscall);
			}
			break;
		default:
			{
				const char *k;
				rc = auparse_first_record(au);
				k = auparse_find_field(au, "key");
				if (k && strcmp(k, "(null)")) {
					act = "triggered-audit-rule";
					D.thing.primary = set_record(0,
						auparse_get_record_num(au));
					D.thing.primary = set_field(
						D.thing.primary,
						auparse_get_field_num(au));
				} else
					act = "triggered-unknown-audit-rule";
				D.thing.what = NORM_WHAT_AUDIT_RULE;
			}
			break;
	}

	// We put the AVC back after gathering the object information
	if (tmp_objkind == NORM_MAC)
		act = "accessed-mac-policy-controlled-object";
	else if (tmp_objkind == NORM_AV)
		act = "accessed-policy-controlled-file";
	
	if (act)
		D.action = strdup(act);

	return 0;
}

static const char *normalize_determine_evkind(int type)
{
	int kind;

	switch (type)
	{
		case AUDIT_USER_AUTH ... AUDIT_USER_ACCT:
		case AUDIT_CRED_ACQ ... AUDIT_USER_END:
		case AUDIT_USER_CHAUTHTOK ... AUDIT_CRED_REFR:
		case AUDIT_USER_LOGIN ... AUDIT_USER_LOGOUT:
		case AUDIT_LOGIN:
			kind = NORM_EVTYPE_USER_LOGIN;
			break;
		case AUDIT_GRP_AUTH:
		case AUDIT_CHGRP_ID:
			kind = NORM_EVTYPE_GROUP_CHANGE;
			break;
		case AUDIT_USER_MGMT:
		case AUDIT_ADD_USER ...AUDIT_DEL_GROUP:
		case AUDIT_GRP_MGMT ... AUDIT_GRP_CHAUTHTOK:
		case AUDIT_ACCT_LOCK ... AUDIT_ACCT_UNLOCK:
			kind = NORM_EVTYPE_USER_ACCT;
			break;
		case AUDIT_KERNEL:
		case AUDIT_SYSTEM_BOOT ... AUDIT_SERVICE_STOP:
			kind = NORM_EVTYPE_SYSTEM_SERVICES;
			break;
		case AUDIT_USYS_CONFIG:
		case AUDIT_CONFIG_CHANGE:
		case AUDIT_NETFILTER_CFG:
		case AUDIT_FEATURE_CHANGE ... AUDIT_REPLACE:
		case AUDIT_USER_DEVICE:
			kind = NORM_EVTYPE_CONFIG;
			break;
		case AUDIT_SECCOMP:
			kind = NORM_EVTYPE_DAC_DECISION;
			break;
		case AUDIT_TEST ... AUDIT_TRUSTED_APP:
		case AUDIT_USER_CMD:
		case AUDIT_CHUSER_ID:
			kind = NORM_EVTYPE_USERSPACE;
			break;
		case AUDIT_USER_TTY:
		case AUDIT_TTY:
			kind = NORM_EVTYPE_TTY;
			break;
		case AUDIT_FIRST_DAEMON ... AUDIT_LAST_DAEMON:
			kind = NORM_EVTYPE_AUDIT_DAEMON;
			break;
		case AUDIT_USER_SELINUX_ERR:
		case AUDIT_USER_AVC:
		case AUDIT_APPARMOR_ALLOWED ... AUDIT_APPARMOR_DENIED:
		case AUDIT_APPARMOR_ERROR:
		case AUDIT_AVC ... AUDIT_AVC_PATH:
			kind = NORM_EVTYPE_MAC_DECISION;
			break;
		case AUDIT_INTEGRITY_FIRST_MSG ... AUDIT_INTEGRITY_LAST_MSG:
		case AUDIT_ANOM_RBAC_INTEGRITY_FAIL: // Aide sends this
			kind = NORM_EVTYPE_INTEGRITY;
			break;
		case AUDIT_FIRST_KERN_ANOM_MSG ... AUDIT_LAST_KERN_ANOM_MSG:
		case AUDIT_FIRST_ANOM_MSG ... AUDIT_ANOM_RBAC_FAIL:
		case AUDIT_ANOM_CRYPTO_FAIL ... AUDIT_LAST_ANOM_MSG:
			kind = NORM_EVTYPE_ANOMALY;
			break;
		case AUDIT_FIRST_ANOM_RESP ... AUDIT_LAST_ANOM_RESP:
			kind = NORM_EVTYPE_ANOMALY_RESP;
			break;
		case AUDIT_MAC_POLICY_LOAD ... AUDIT_LAST_SELINUX:
		case AUDIT_AA ... AUDIT_APPARMOR_AUDIT:
		case AUDIT_APPARMOR_HINT ... AUDIT_APPARMOR_STATUS:
		case AUDIT_FIRST_USER_LSPP_MSG ... AUDIT_LAST_USER_LSPP_MSG:
			kind = NORM_EVTYPE_MAC;
			break;
		case AUDIT_FIRST_KERN_CRYPTO_MSG ... AUDIT_LAST_KERN_CRYPTO_MSG:
		case AUDIT_FIRST_CRYPTO_MSG ... AUDIT_LAST_CRYPTO_MSG:
			kind = NORM_EVTYPE_CRYPTO;
			break;
		case AUDIT_FIRST_VIRT_MSG ... AUDIT_LAST_VIRT_MSG:
			kind = NORM_EVTYPE_VIRT;
			break;
		case AUDIT_SYSCALL ... AUDIT_SOCKETCALL:
		case AUDIT_SOCKADDR ... AUDIT_MQ_GETSETATTR:
		case AUDIT_FD_PAIR ... AUDIT_OBJ_PID:
		case AUDIT_BPRM_FCAPS ... AUDIT_NETFILTER_PKT:
			kind = NORM_EVTYPE_AUDIT_RULE;
			break;
		case AUDIT_FANOTIFY:
			kind = NORM_EVTYPE_AV_DECISION;
			break;
		default:
			kind = NORM_EVTYPE_UNKNOWN;
	}

	return evtype_i2s(kind);
}

static int normalize_compound(auparse_state_t *au)
{
	const char *f, *syscall = NULL;
	int rc, recno, otype, type;

	otype = type = auparse_get_type(au);

	// All compound events have a syscall record
	// Some start with a record type and follow with a syscall
	if (type == AUDIT_NETFILTER_CFG || type == AUDIT_ANOM_PROMISCUOUS ||
		type == AUDIT_AVC || type == AUDIT_SELINUX_ERR ||
		type == AUDIT_MAC_POLICY_LOAD || type == AUDIT_MAC_STATUS ||
		type == AUDIT_MAC_CONFIG_CHANGE || type == AUDIT_FANOTIFY) {
		auparse_next_record(au);
		type = auparse_get_type(au);
	} else if (type == AUDIT_ANOM_LINK) {
		auparse_next_record(au);
		auparse_next_record(au);
		type = auparse_get_type(au);
	}

	// Determine the kind of event using original event type
	D.evkind = normalize_determine_evkind(otype);

	if (type == AUDIT_SYSCALL) {
		recno = auparse_get_record_num(au);
		f = auparse_find_field(au, "syscall");
		if (f) {
			f = auparse_interpret_field(au);
			if (f)
				syscall = strdup(f);
		}

		// Results
		f = auparse_find_field(au, "success");
		if (f) {
			const char *str = auparse_get_field_str(au);
			if (strcmp(str, "no") == 0)
				syscall_success = 0;
			else
				syscall_success = 1;

			D.results = set_record(0, recno);
			D.results = set_field(D.results,
					auparse_get_field_num(au));
		} else {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free((void *)syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		// Subject - primary
		if (set_prime_subject(au, "auid", recno)) {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free((void *)syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		// Subject - alias, uid comes before auid
		if (set_secondary_subject(au, "uid", recno)) {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free((void *)syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		// Subject attributes
		syscall_subj_attr(au);

		// how
		auparse_first_field(au);
		f = auparse_find_field(au, "exe");
		if (f) {
			const char *exe = auparse_interpret_field(au);
			D.how = strdup(exe);
			if ((strncmp(D.how, "/usr/bin/python", 15) == 0) ||
			    (strncmp(D.how, "/usr/bin/sh", 11) == 0) ||
			    (strncmp(D.how, "/usr/bin/bash", 13) == 0) ||
			    (strncmp(D.how, "/usr/bin/perl", 13) == 0)) {
				int fnum;
				rc = 0;
				// Comm should be the previous field
				if ((fnum = auparse_get_field_num(au)) > 0)
					rc = auparse_goto_field_num(au,fnum-1);
				if (rc == 0)
					auparse_first_record(au);
				f = auparse_find_field(au, "comm");
				if (f) {
					free((void *)D.how);
					exe = auparse_interpret_field(au);
					D.how = strdup(exe);
				}
			}
		} else {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free((void *)syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		f = auparse_find_field(au, "key");
		if (f) {
			const char *k = auparse_get_field_str(au);
			if (strcmp(k, "(null)")) {
				// We only collect real keys
				D.key = set_record(0, recno);
				D.key = set_field(D.key,
						auparse_get_field_num(au));
			}
		} // No error repositioning will be done because nothing
		  // below uses fields.

		// action & object
		if (otype == AUDIT_ANOM_LINK) {
			const char *act = normalize_record_map_i2s(otype);
			if (act)
				D.action = strdup(act);
			// FIXME: AUDIT_ANOM_LINK needs an object
		} else
			normalize_syscall(au, syscall);
	}

	free((void *)syscall);
	return 0;
}

static value_t find_simple_object(auparse_state_t *au, int type)
{
	value_t o = set_record(0, UNSET);
	const char *f = NULL;

	auparse_first_field(au);
	switch (type)
	{
		case AUDIT_SERVICE_START:
		case AUDIT_SERVICE_STOP:
			f = auparse_find_field(au, "unit");
			D.thing.what = NORM_WHAT_SERVICE;
			break;
		case AUDIT_SYSTEM_RUNLEVEL:
			f = auparse_find_field(au, "new-level");
			D.thing.what = NORM_WHAT_SYSTEM;
			break;
		case AUDIT_USER_ROLE_CHANGE:
			f = auparse_find_field(au, "selected-context");
			D.thing.what = NORM_WHAT_USER_SESSION;
			break;
		case AUDIT_ROLE_ASSIGN:
		case AUDIT_ROLE_REMOVE:
		case AUDIT_USER_MGMT:
		case AUDIT_ACCT_LOCK:
		case AUDIT_ACCT_UNLOCK:
		case AUDIT_ADD_USER:
		case AUDIT_DEL_USER:
		case AUDIT_ADD_GROUP:
		case AUDIT_DEL_GROUP:
		case AUDIT_GRP_MGMT:
			f = auparse_find_field(au, "id");
			if (f == NULL) {
				auparse_first_record(au);
				f = auparse_find_field(au, "acct");
			}
			D.thing.what = NORM_WHAT_ACCT;
			break;
		case AUDIT_USER_START:
		case AUDIT_USER_END:
		case AUDIT_USER_ERR:
		case AUDIT_USER_LOGIN:
		case AUDIT_USER_LOGOUT:
			f = auparse_find_field(au, "terminal");
			D.thing.what = NORM_WHAT_USER_SESSION;
			break;
		case AUDIT_USER_AUTH:
		case AUDIT_USER_ACCT:
		case AUDIT_CRED_ACQ:
		case AUDIT_CRED_REFR:
		case AUDIT_CRED_DISP:
		case AUDIT_USER_CHAUTHTOK:
		case AUDIT_GRP_CHAUTHTOK:
		case AUDIT_ANOM_LOGIN_FAILURES:
		case AUDIT_ANOM_LOGIN_TIME:
		case AUDIT_ANOM_LOGIN_SESSIONS:
		case AUDIT_ANOM_LOGIN_LOCATION:
			f = auparse_find_field(au, "acct");
			D.thing.what = NORM_WHAT_USER_SESSION;
			break;
		case AUDIT_ANOM_EXEC:
		case AUDIT_USER_CMD:
			f = auparse_find_field(au, "cmd");
			D.thing.what = NORM_WHAT_PROCESS;
			break;
		case AUDIT_USER_TTY:
		case AUDIT_TTY:
			auparse_first_record(au);
			f = auparse_find_field(au, "data");
			D.thing.what = NORM_WHAT_KEYSTROKES;
			break;
		case AUDIT_USER_DEVICE:
			auparse_first_record(au);
			f = auparse_find_field(au, "device");
			D.thing.what = NORM_WHAT_KEYSTROKES;
			break;
		case AUDIT_VIRT_MACHINE_ID:
			f = auparse_find_field(au, "vm");
			D.thing.what = NORM_WHAT_VM;
			break;
		case AUDIT_VIRT_RESOURCE:
			f = auparse_find_field(au, "resrc");
			D.thing.what = NORM_WHAT_VM;
			break;
		case AUDIT_VIRT_CONTROL:
			f = auparse_find_field(au, "op");
			D.thing.what = NORM_WHAT_VM;
			break;
		case AUDIT_LABEL_LEVEL_CHANGE:
			f = auparse_find_field(au, "printer");
			D.thing.what = NORM_WHAT_PRINTER;
			break;
		case AUDIT_CONFIG_CHANGE:
			f = auparse_find_field(au, "key");
			if (f == NULL) {
				auparse_first_record(au);
				f = auparse_find_field(au, "audit_enabled");
				if (f == NULL) {
					auparse_first_record(au);
					f = auparse_find_field(au, "audit_pid");
					if (f == NULL) {
						auparse_first_record(au);
						f = auparse_find_field(au,
							"audit_backlog_limit");
						if (f == NULL) {
						    auparse_first_record(au);
						    f = auparse_find_field(au,
							"audit_failure");
						}
					}
				}
			}
			D.thing.what = NORM_WHAT_AUDIT_CONFIG;
			break;
		case AUDIT_MAC_CONFIG_CHANGE:
			f = auparse_find_field(au, "bool");
			D.thing.what = NORM_WHAT_MAC_CONFIG;
			break;
		case AUDIT_MAC_STATUS:
			f = auparse_find_field(au, "enforcing");
			D.thing.what = NORM_WHAT_MAC_CONFIG;
			break;
		// These deal with policy, not sure about object yet
		case AUDIT_MAC_POLICY_LOAD:
		case AUDIT_LABEL_OVERRIDE:
		case AUDIT_DEV_ALLOC ... AUDIT_USER_MAC_CONFIG_CHANGE:
			D.thing.what = NORM_WHAT_MAC_CONFIG;
			break;
		case AUDIT_USER:
			f = auparse_find_field(au, "addr");
			// D.thing.what = NORM_WHAT_?
			break;
		case AUDIT_USYS_CONFIG:
			f = auparse_find_field(au, "op");
			if (f) {
				free((void *)D.action);
				D.action = strdup(auparse_interpret_field(au));
				f = NULL;
			}
			D.thing.what = NORM_WHAT_SYSTEM;
			break;
		case AUDIT_CRYPTO_KEY_USER:
			f = auparse_find_field(au, "fp");
			D.thing.what = NORM_WHAT_USER_SESSION;
			break;
		case AUDIT_CRYPTO_SESSION:
			f = auparse_find_field(au, "addr");
			D.thing.what = NORM_WHAT_USER_SESSION;
			break;
		case AUDIT_ANOM_RBAC_INTEGRITY_FAIL:
			f = auparse_find_field(au, "hostname");
			D.thing.what = NORM_WHAT_FILESYSTEM;
			break;
		default:
			break;
	}
	if (f) {
		o = set_record(0, 0);
		o = set_field(o, auparse_get_field_num(au));
	}
	return o;
}

static value_t find_simple_obj_secondary(auparse_state_t *au, int type)
{
	value_t o = set_record(0, UNSET);
	const char *f = NULL;

	// FIXME: maybe pass flag indicating if this is needed
	auparse_first_field(au);
	switch (type)
	{
		case AUDIT_CRYPTO_SESSION:
			f = auparse_find_field(au, "rport");
			break;
		default:
			break;
	}
	if (f) {
		o = set_record(0, 0);
		o = set_field(o, auparse_get_field_num(au));
	}
	return o;
}

static value_t find_simple_obj_primary2(auparse_state_t *au, int type)
{
	value_t o = set_record(0, UNSET);
	const char *f = NULL;

	// FIXME: maybe pass flag indicating if this is needed
	auparse_first_field(au);
	switch (type)
	{
		case AUDIT_VIRT_CONTROL:
			f = auparse_find_field(au, "vm");
			break;
		case AUDIT_VIRT_RESOURCE:
			f = auparse_find_field(au, "vm");
			break;
		default:
			break;
	}
	if (f) {
		o = set_record(0, 0);
		o = set_field(o, auparse_get_field_num(au));
	}
	return o;
}

static void collect_simple_subj_attr(auparse_state_t *au)
{
        if (D.opt == NORM_OPT_NO_ATTRS)
                return;

        auparse_first_record(au);
	add_subj_attr(au, "pid", 0); // Just pass 0 since simple is 1 record
	add_subj_attr(au, "subj", 0);
}

static void collect_userspace_subj_attr(auparse_state_t *au, int type)
{
        if (D.opt == NORM_OPT_NO_ATTRS)
                return;

	// Just pass 0 since simple is 1 record
	add_subj_attr(au, "hostname", 0);
	add_subj_attr(au, "addr", 0);

	// Some events have the terminal as the object - skip for them
	if (type != AUDIT_USER_START && type != AUDIT_USER_END &&
				type != AUDIT_USER_ERR)
		add_subj_attr(au, "terminal", 0);
}

static int normalize_simple(auparse_state_t *au)
{
	const char *f, *act = NULL;
	int type = auparse_get_type(au);

	// netfilter_cfg sometimes emits 1 record events
	if (type == AUDIT_NETFILTER_CFG)
		return 1;

	// Some older OS do not have PROCTITLE records
	if (type == AUDIT_SYSCALL)
		return normalize_compound(au);

	// Determine the kind of event
	D.evkind = normalize_determine_evkind(type);

	// This is for events that follow:
	// auid, (op), (uid), stuff
	if (type == AUDIT_CONFIG_CHANGE || type == AUDIT_FEATURE_CHANGE ||
			type == AUDIT_SECCOMP || type == AUDIT_ANOM_ABEND) {
		// Subject - primary
		set_prime_subject(au, "auid", 0);

		// Session
		add_session(au, 0);

		// Subject attrs
		collect_simple_subj_attr(au);

		// action
		if (type == AUDIT_CONFIG_CHANGE) {
			auparse_first_field(au);
			f = auparse_find_field(au, "op");
			if (f) {
				const char *str = auparse_interpret_field(au);
				if (*str == '"')
					str++;
				if (strncmp(str, "add_rule", 8) == 0) {
					D.action = strdup("added-audit-rule");
					D.thing.primary =
						find_simple_object(au, type);
				} else if (strncmp(str,"remove_rule",11) == 0){
					D.action = strdup("deleted-audit-rule");
					D.thing.primary =
						find_simple_object(au, type);
				} else
					goto map;
			} else
				goto map;
		} else { // This assigns action for feature_change, seccomp,
			 // and anom_abend
map:
			act = normalize_record_map_i2s(type);
			if (act)
				D.action = strdup(act);
			if (type == AUDIT_CONFIG_CHANGE)
				D.thing.primary = find_simple_object(au, type);
			auparse_first_record(au);
		}

		// object
		if (type == AUDIT_FEATURE_CHANGE) {
			// Subject - secondary
			auparse_first_field(au);
			if (set_secondary_subject(au, "uid", 0))
				auparse_first_record(au);

			// how
			f = auparse_find_field(au, "exe");
			if (f) {
				const char *sig = auparse_interpret_field(au);
				D.how = strdup(sig);
			}

			// object
			set_prime_object(au, "feature", 0);
			D.thing.what = NORM_WHAT_SYSTEM;
		}

		if (type == AUDIT_SECCOMP) {
			// Subject - secondary
			auparse_first_field(au);
			if (set_secondary_subject(au, "uid", 0))
				auparse_first_record(au);

			// how
			f = auparse_find_field(au, "exe");
			if (f) {
				const char *sig = auparse_interpret_field(au);
				D.how = strdup(sig);
			}

			// Object
			if (set_prime_object(au, "syscall", 0))
				auparse_first_record(au);
			D.thing.what = NORM_WHAT_PROCESS;

			// Results
			f = auparse_find_field(au, "code");
			if (f) {
				D.results = set_record(0, 0);
				D.results = set_field(D.results,
						auparse_get_field_num(au));
			}
			return 0;
		}

		if (type == AUDIT_ANOM_ABEND) {
			// Subject - secondary
			auparse_first_field(au);
			if (set_secondary_subject(au, "uid", 0))
				auparse_first_record(au);

			//object
			if (set_prime_object(au, "exe", 0))
				auparse_first_record(au);
			D.thing.what = NORM_WHAT_PROCESS;

			// how
			f = auparse_find_field(au, "sig");
			if (f) {
				const char *sig = auparse_interpret_field(au);
				D.how = strdup(sig);
			}
		}

		// Results
		set_results(au, 0);

		return 0;
	}

	// This one is atypical and originates from the kernel
	if (type == AUDIT_LOGIN) {
		// Secondary
		if (set_secondary_subject(au, "uid", 0))
			auparse_first_record(au);

		// Subject attrs
		collect_simple_subj_attr(au);

		// Subject
		if (set_prime_subject(au, "old-auid", 0))
			auparse_first_record(au);

		// Object
		if (set_prime_object(au, "auid", 0))
			auparse_first_record(au);
		D.thing.what = NORM_WHAT_USER_SESSION;

		// Session
		add_session(au, 0);

		// Results
		set_results(au, 0);

		// action
		act = normalize_record_map_i2s(type);
		if (act)
			D.action = strdup(act);

		// How - currently missing

		return 0;
	}

	/* This one is also atypical and comes from the kernel */
	if (type == AUDIT_AVC) {
		// how
		f = auparse_find_field(au, "comm");
		if (f) {
			const char *sig = auparse_interpret_field(au);
			D.how = strdup(sig);
		} else
			auparse_first_record(au);

		// Subject
		if (set_prime_subject(au, "scontext", 0))
			auparse_first_record(au);

		// Object
		if (D.opt == NORM_OPT_ALL) {
			// We will only collect this when everything is asked
			// for because it messes up text format otherwise
			if (set_prime_object(au, "tcontext", 0))
				auparse_first_record(au);
		}

		// action
		act = normalize_record_map_i2s(type);
		if (act)
			D.action = strdup(act);

		// This is slim pickings without a syscall record
		return 0;
	}

	/* Daemon events are atypical because they never transit the kernel */
	if (type >= AUDIT_FIRST_DAEMON && 
		type < AUDIT_LAST_DAEMON) {
		// Subject - primary
		set_prime_subject(au, "auid", 0);

		// Secondary - optional
		if (set_secondary_subject(au, "uid", 0))
			auparse_first_record(au);

		// Session - optional
		if (add_session(au, 0))
			auparse_first_record(au);

		// Subject attrs
		collect_simple_subj_attr(au);

		// action
		act = normalize_record_map_i2s(type);
		if (act)
			D.action = strdup(act);

		// Object type
		D.thing.what = NORM_WHAT_SERVICE;

		// Results
		set_results(au, 0);
		return 0;
	}

	// This is for events that follow:
	// uid, auid, ses, res, find_simple_object
	//
	// USER_LOGIN is different in locating the subject because if they
	// fail login, they are not quite in the system to have an auid.
	if (type == AUDIT_USER_LOGIN) {
		// Subject - primary
		if (set_prime_subject(au, "id", 0)) {
			auparse_first_record(au);
			if (set_prime_subject(au, "acct", 0) == 0)
				set_subject_what(au);
		} else // If id found, set the subjkind
			set_subject_what(au);
		auparse_first_record(au);
	} else {
		// Subject - alias, uid comes before auid
		if (set_secondary_subject(au, "uid", 0))
			auparse_first_record(au);

		// Subject - primary
		set_prime_subject(au, "auid", 0);
	}
	// Session
	add_session(au, 0);

	// Subject attrs
	collect_simple_subj_attr(au);
	if ((type >= AUDIT_FIRST_USER_MSG && type < AUDIT_LAST_USER_MSG) ||
		(type >= AUDIT_FIRST_USER_MSG2 && type < AUDIT_LAST_USER_MSG2))
		collect_userspace_subj_attr(au, type);

	// Results
	set_results(au, 0);

	// action
	if (type == AUDIT_USER_DEVICE) {
		auparse_first_record(au);
		f = auparse_find_field(au, "op");
		if (f)
			act = f;
	}
	if (act == NULL)
		act = normalize_record_map_i2s(type);
	if (act)
		D.action = strdup(act);

	// object
	D.thing.primary = find_simple_object(au, type);
	D.thing.secondary = find_simple_obj_secondary(au, type);
	D.thing.two = find_simple_obj_primary2(au, type);

	// object attrs - rare on simple events
	if (D.opt == NORM_OPT_ALL) {
		if (type == AUDIT_USER_DEVICE) {
			add_obj_attr(au, "uuid", 0);
		}
	}

	// how
	if (type == AUDIT_SYSTEM_BOOT) {
		D.thing.what = NORM_WHAT_SYSTEM;
		return 0;
	} else if (type == AUDIT_SYSTEM_SHUTDOWN) {
		D.thing.what = NORM_WHAT_SERVICE;
		return 0;
	}
	auparse_first_record(au);
	if (type == AUDIT_ANOM_EXEC) {
		f = auparse_find_field(au, "terminal");
		if (f) {
			const char *term = auparse_interpret_field(au);
			D.how = strdup(term);
		}
		return 0;
	}
	if (type == AUDIT_TTY) {
		f = auparse_find_field(au, "comm");
		if (f) {
			const char *comm = auparse_interpret_field(au);
			D.how = strdup(comm);
		}
		return 0;
	}
	f = auparse_find_field(au, "exe");
	if (f) {
		const char *exe = auparse_interpret_field(au);
		D.how = strdup(exe);
		if ((strncmp(D.how, "/usr/bin/python", 15) == 0) ||
		    (strncmp(D.how, "/usr/bin/sh", 11) == 0) ||
		    (strncmp(D.how, "/usr/bin/bash", 13) == 0) ||
		    (strncmp(D.how, "/usr/bin/perl", 13) == 0)) {
                        // comm should be the previous field if its there at all
                        int fnum;
			if ((fnum = auparse_get_field_num(au)) > 0)
				auparse_goto_field_num(au, fnum - 1);
			else
				auparse_first_record(au);
			f = auparse_find_field(au, "comm");
			if (f) {
				free((void *)D.how);
				exe = auparse_interpret_field(au);
				D.how = strdup(exe);
			}
		}
	}

	return 0;
}

/*
 * This is the main entry point for the normalization. This function
 * will analyze the current record to pick out the important pieces.
 */
int auparse_normalize(auparse_state_t *au, normalize_option_t opt)
{
	int rc;
	unsigned num;

	auparse_first_record(au);
	num = auparse_get_num_records(au);

	// Reset cursor - no idea what we are being handed
	auparse_first_record(au);
	clear_normalizer(&D);
	D.opt = opt;

	// If we have more than one record in the event its a syscall based
	// event. Otherwise its a simple event with all pieces in the same
	// record.
	if (num > 1)
		rc = normalize_compound(au);
	else
		rc = normalize_simple(au);	

	// Reset the cursor
	auparse_first_record(au);
	return rc;
}

/*
 * This function positions the internal cursor to the record and field that
 * the location refers to.
 * Returns: < 0 error, 0 uninitialized, 1 == success
 */
static int seek_field(auparse_state_t *au, value_t location)
{
	int record, field, rc;

	if (is_unset(location))
		return 0;

	record = get_record(location);
	field = get_field(location);

	rc = auparse_goto_record_num(au, record);
	if (rc != 1)
		return -1;

	rc = auparse_goto_field_num(au, field);
	if (rc != 1)
		return -2;

	return 1;
}

const char *auparse_normalize_get_event_kind(auparse_state_t *au)
{
	return D.evkind;
}

int auparse_normalize_session(auparse_state_t *au)
{
	return seek_field(au, D.session);
}

int auparse_normalize_subject_primary(auparse_state_t *au)
{
	return seek_field(au, D.actor.primary);
}

int auparse_normalize_subject_secondary(auparse_state_t *au)
{
	return seek_field(au, D.actor.secondary);
}

const char *auparse_normalize_subject_kind(auparse_state_t *au)
{
	return D.actor.what;
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_normalize_subject_first_attribute(auparse_state_t *au)
{
	if (D.actor.attr.cnt) {
		data_node *n;

		cllist_first(&D.actor.attr);
		n = cllist_get_cur(&D.actor.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_normalize_subject_next_attribute(auparse_state_t *au)
{
	if (D.actor.attr.cnt) {
		data_node *n;

		n = cllist_next(&D.actor.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

const char *auparse_normalize_get_action(auparse_state_t *au)
{
	return D.action;
}

int auparse_normalize_object_primary(auparse_state_t *au)
{
	return seek_field(au, D.thing.primary);
}

int auparse_normalize_object_secondary(auparse_state_t *au)
{
	return seek_field(au, D.thing.secondary);
}

int auparse_normalize_object_primary2(auparse_state_t *au)
{
	return seek_field(au, D.thing.two);
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_normalize_object_first_attribute(auparse_state_t *au)
{
	if (D.thing.attr.cnt) {
		data_node *n;

		cllist_first(&D.thing.attr);
		n = cllist_get_cur(&D.thing.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_normalize_object_next_attribute(auparse_state_t *au)
{
	if (D.thing.attr.cnt) {
		data_node *n;

		n = cllist_next(&D.thing.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

const char *auparse_normalize_object_kind(auparse_state_t *au)
{
	return normalize_obj_kind_map_i2s(D.thing.what);
}

int auparse_normalize_get_results(auparse_state_t *au)
{
	return seek_field(au, D.results);
}

const char *auparse_normalize_how(auparse_state_t *au)
{
	return D.how;
}

int auparse_normalize_key(auparse_state_t *au)
{
	return seek_field(au, D.key);
}
