/* auditctl-listing.c -- 
 * Copyright 2014,16 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auditctl-listing.h"
#include "private.h"
#include "auditctl-llist.h"
#include "auparse-idata.h"

/* Global vars */
static llist l;
static int printed;
extern int list_requested, interpret;
extern char key[AUDIT_MAX_KEY_LEN+1];
extern const char key_sep[2];

/*
 * Returns 1 if rule should be printed & 0 if not
 */
int key_match(const struct audit_rule_data *r)
{
	unsigned int i;
	size_t boffset = 0;

	if (key[0] == 0)
		return 1;

	// At this point, we have a key
	for (i = 0; i < r->field_count; i++) {
		int field = r->fields[i] & ~AUDIT_OPERATORS;
		if (field == AUDIT_FILTERKEY) {
			char *keyptr;
			if (asprintf(&keyptr, "%.*s", r->values[i],
				     &r->buf[boffset]) < 0)
				keyptr = NULL;
			else if (strstr(keyptr, key)) {
				free(keyptr);
				return 1;
			}
			free(keyptr);
		}
		if (((field >= AUDIT_SUBJ_USER && field <= AUDIT_OBJ_LEV_HIGH)
                     && field != AUDIT_PPID) || field == AUDIT_WATCH ||
			field == AUDIT_DIR || field == AUDIT_FILTERKEY
		     || field == AUDIT_EXE) {
				boffset += r->values[i];
		}
	}
	return 0;
}

/*
 * This function detects if we have a watch. A watch is detected when we
 * have syscall == all and a perm field.
 */
static int is_watch(const struct audit_rule_data *r)
{
	unsigned int i, perm = 0, all = 1;

	for (i = 0; i < r->field_count; i++) {
		int field = r->fields[i] & ~AUDIT_OPERATORS;
		if (field == AUDIT_PERM)
			perm = 1;
		// Watches can have only 4 field types
		if (field != AUDIT_PERM && field != AUDIT_FILTERKEY &&
			field != AUDIT_DIR && field != AUDIT_WATCH)
			return 0;
	}

	if (((r->flags & AUDIT_FILTER_MASK) != AUDIT_FILTER_USER) &&
		((r->flags & AUDIT_FILTER_MASK) != AUDIT_FILTER_TASK) &&
		((r->flags & AUDIT_FILTER_MASK) != AUDIT_FILTER_EXCLUDE) &&
		((r->flags & AUDIT_FILTER_MASK) != AUDIT_FILTER_FS)) {
		for (i = 0; i < (AUDIT_BITMASK_SIZE-1); i++) {
			if (r->mask[i] != (uint32_t)~0) {
				all = 0;
				break;
			}
		}
	}
	if (perm && all)
		return 1;
	return 0;
}

static int print_arch(unsigned int value, int op)
{
	int machine;
	_audit_elf = value;
	machine = audit_elf_to_machine(_audit_elf);
	if (machine < 0)
		printf(" -F arch%s0x%X", audit_operator_to_symbol(op),
				(unsigned)value);
	else {
		if (interpret == 0) {
			if (__AUDIT_ARCH_64BIT & _audit_elf)
				printf(" -F arch%sb64",
						audit_operator_to_symbol(op));
			else
				printf(" -F arch%sb32",
						audit_operator_to_symbol(op));
		} else {	
			const char *ptr = audit_machine_to_name(machine);
			printf(" -F arch%s%s", audit_operator_to_symbol(op),
						ptr);
		}
	}
	return machine;
}

static int print_syscall(const struct audit_rule_data *r, unsigned int *sc)
{
	int count = 0;
	int all = 1;
	unsigned int i;
	int machine = audit_detect_machine();

	/* Rules on the following filters do not take a syscall */
	if (((r->flags & AUDIT_FILTER_MASK) == AUDIT_FILTER_USER) ||
	    ((r->flags & AUDIT_FILTER_MASK) == AUDIT_FILTER_TASK) ||
	    ((r->flags &AUDIT_FILTER_MASK) == AUDIT_FILTER_EXCLUDE) ||
	    ((r->flags &AUDIT_FILTER_MASK) == AUDIT_FILTER_FS))
		return 0;

	/* See if its all or specific syscalls */
	for (i = 0; i < (AUDIT_BITMASK_SIZE-1); i++) {
		if (r->mask[i] != (uint32_t)~0) {
			all = 0;
			break;
		}
	}

	if (all) {
		printf(" -S all");
		count = i;
	} else for (i = 0; i < AUDIT_BITMASK_SIZE * 32; i++) {
		int word = AUDIT_WORD(i);
		int bit  = AUDIT_BIT(i);
		if (r->mask[word] & bit) {
			const char *ptr;
			if (_audit_elf)
				machine = audit_elf_to_machine(_audit_elf);
			if (machine < 0)
				ptr = NULL;
			else
				ptr = audit_syscall_to_name(i, machine);
			if (!count)
				printf(" -S ");
			if (ptr)
				printf("%s%s", !count ? "" : ",", ptr);
			else
				printf("%s%u", !count ? "" : ",", i);
			count++;
			*sc = i;
		}
	}
	return count;
}

static void print_field_cmp(int value, int op)
{
	switch (value)
	{
		case AUDIT_COMPARE_UID_TO_OBJ_UID:
			printf(" -C uid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_OBJ_GID:
			printf(" -C gid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EUID_TO_OBJ_UID:
			printf(" -C euid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EGID_TO_OBJ_GID:
			printf(" -C egid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_OBJ_UID:
			printf(" -C auid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SUID_TO_OBJ_UID:
			printf(" -C suid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SGID_TO_OBJ_GID:
			printf(" -C sgid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_FSUID_TO_OBJ_UID:
			printf(" -C fsuid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_FSGID_TO_OBJ_GID:
			printf(" -C fsgid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_AUID:
			printf(" -C uid%sauid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_EUID:
			printf(" -C uid%seuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_FSUID:
			printf(" -C uid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_SUID:
			printf(" -C uid%ssuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_FSUID:
			printf(" -C auid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_SUID:
			printf(" -C auid%ssuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_EUID:
			printf(" -C auid%seuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EUID_TO_SUID:
			printf(" -C euid%ssuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EUID_TO_FSUID:
			printf(" -C euid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SUID_TO_FSUID:
			printf(" -C suid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_EGID:
			printf(" -C gid%segid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_FSGID:
			printf(" -C gid%sfsgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_SGID:
			printf(" -C gid%ssgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EGID_TO_FSGID:
			printf(" -C egid%sfsgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EGID_TO_SGID:
			printf(" -C egid%ssgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SGID_TO_FSGID:
			printf(" -C sgid%sfsgid",
				audit_operator_to_symbol(op));
			break;
	}
}

/*
 *  This function prints 1 rule from the kernel reply
 */
static void print_rule(const struct audit_rule_data *r)
{
	unsigned int i, count = 0, sc = 0;
	size_t boffset = 0;
	int mach = -1, watch = is_watch(r);
	unsigned long long a0 = 0, a1 = 0;

	if (!watch) { /* This is syscall auditing */
		printf("-a %s,%s",
			audit_action_to_name((int)r->action),
				audit_flag_to_name(r->flags));

		// Now find the arch and print it
		for (i = 0; i < r->field_count; i++) {
			int field = r->fields[i] & ~AUDIT_OPERATORS;
			if (field == AUDIT_ARCH) {
				int op = r->fieldflags[i] & AUDIT_OPERATORS;
				mach = print_arch(r->values[i], op);
			}
		}
		// And last do the syscalls
		count = print_syscall(r, &sc);
	}

	// Now iterate over the fields
	for (i = 0; i < r->field_count; i++) {
		const char *name;
		int op = r->fieldflags[i] & AUDIT_OPERATORS;
		int field = r->fields[i] & ~AUDIT_OPERATORS;

		if (field == AUDIT_ARCH)
			continue;	// already printed

		name = audit_field_to_name(field);
		if (name) {
			// Special cases to print the different field types
			// in a meaningful way.
			if (field == AUDIT_MSGTYPE) {
				if (!audit_msg_type_to_name(r->values[i]))
					printf(" -F %s%s%d", name,
						audit_operator_to_symbol(op),
						r->values[i]);
				else
					printf(" -F %s%s%s", name,
						audit_operator_to_symbol(op),
						audit_msg_type_to_name(
						r->values[i]));
			} else if ((field >= AUDIT_SUBJ_USER &&
						field <= AUDIT_OBJ_LEV_HIGH)
						&& field != AUDIT_PPID) {
				printf(" -F %s%s%.*s", name,
						audit_operator_to_symbol(op),
						r->values[i], &r->buf[boffset]);
				boffset += r->values[i];
			} else if (field == AUDIT_WATCH) {
				if (watch)
					printf("-w %.*s", r->values[i],
						&r->buf[boffset]);
				else
					printf(" -F path=%.*s",	r->values[i],
						&r->buf[boffset]);
				boffset += r->values[i];
			} else if (field == AUDIT_DIR) {
				if (watch)
					printf("-w %.*s", r->values[i],
						&r->buf[boffset]);
				else
					printf(" -F dir=%.*s", r->values[i],
						&r->buf[boffset]);

				boffset += r->values[i];
			} else if (field == AUDIT_EXE) {
				printf(" -F exe=%.*s",
					r->values[i], &r->buf[boffset]);
				boffset += r->values[i];
			} else if (field == AUDIT_FILTERKEY) {
				char *rkey, *ptr, *saved;
				if (asprintf(&rkey, "%.*s", r->values[i],
					      &r->buf[boffset]) < 0)
					rkey = NULL;
				boffset += r->values[i];
				ptr = strtok_r(rkey, key_sep, &saved);
				while (ptr) {
					if (watch)
						printf(" -k %s", ptr);
					else
						printf(" -F key=%s", ptr);
					ptr = strtok_r(NULL, key_sep, &saved);
				}
				free(rkey);
			} else if (field == AUDIT_PERM) {
				char perms[5];
				int val=r->values[i];
				perms[0] = 0;
				if (val & AUDIT_PERM_READ)
					strcat(perms, "r");
				if (val & AUDIT_PERM_WRITE)
					strcat(perms, "w");
				if (val & AUDIT_PERM_EXEC)
					strcat(perms, "x");
				if (val & AUDIT_PERM_ATTR)
					strcat(perms, "a");
				if (watch)
					printf(" -p %s", perms);
				else
					printf(" -F perm=%s", perms);
			} else if (field == AUDIT_INODE) {
				// This is unsigned
				printf(" -F %s%s%u", name, 
						audit_operator_to_symbol(op),
						r->values[i]);
			} else if (field == AUDIT_FIELD_COMPARE) {
				print_field_cmp(r->values[i], op);
			} else if (field >= AUDIT_ARG0 && field <= AUDIT_ARG3){
				if (field == AUDIT_ARG0)
					a0 = r->values[i];
				else if (field == AUDIT_ARG1)
					a1 = r->values[i];

				// Show these as hex
				if (count > 1 || interpret == 0)
					printf(" -F %s%s0x%X", name, 
						audit_operator_to_symbol(op),
						r->values[i]);
				else {	// Use ignore to mean interpret
					const char *out;
					idata id;
					char val[32];
					int type;

					id.syscall = sc;
					id.machine = mach;
					id.a0 = a0;
					id.a1 = a1;
					id.name = name;
					id.cwd = NULL;
					snprintf(val, 32, "%x", r->values[i]);
					id.val = val;
					type = auparse_interp_adjust_type(
						AUDIT_SYSCALL, name, val);
					out = auparse_do_interpretation(type,
							&id,
							AUPARSE_ESC_TTY);
					printf(" -F %s%s%s", name,
						audit_operator_to_symbol(op),
								out);
					free((void *)out);
				}
			} else if (field == AUDIT_EXIT) {
				int e = abs((int)r->values[i]);
				const char *err = audit_errno_to_name(e);

				if (((int)r->values[i] < 0) && err)
					printf(" -F %s%s-%s", name,
						audit_operator_to_symbol(op),
						err);
				else
					printf(" -F %s%s%d", name,
						audit_operator_to_symbol(op),
						(int)r->values[i]);
			} else if (field == AUDIT_FSTYPE) {
				if (!audit_fstype_to_name(r->values[i]))
					printf(" -F %s%s%d", name,
						audit_operator_to_symbol(op),
						r->values[i]);
				else
					printf(" -F %s%s%s", name,
						audit_operator_to_symbol(op),
						audit_fstype_to_name(
						r->values[i]));
			} else {
				// The default is signed decimal
				printf(" -F %s%s%d", name, 
						audit_operator_to_symbol(op),
						r->values[i]);
			}
		} else {
			 // The field name is unknown 
			printf(" f%d%s%d", r->fields[i],
						audit_operator_to_symbol(op),
						r->values[i]);
		}
	}
	printf("\n");
}

void audit_print_init(void)
{
	printed = 0;
	list_create(&l);
}

const char *get_enable(unsigned e)
{
	switch (e)
	{
		case 0:
			return "disable";
		case 1:
			return "enabled";
		case 2:
			return "enabled+immutable";
		default:
			return "unknown";
	}
}

const char *get_failure(unsigned f)
{
	switch (f)
	{
		case 0:
			return "silent";
		case 1:
			return "printk";
		case 2:
			return "panic";
		default:
			return "unknown";
	}
}

/*
 * This function interprets the reply and prints it to stdout. It returns
 * 0 if no more should be read and 1 to indicate that more messages of this
 * type may need to be read. 
 */
int audit_print_reply(struct audit_reply *rep, int fd)
{
	_audit_elf = 0; 

	switch (rep->type) {
		case NLMSG_NOOP:
			return 1;
		case NLMSG_DONE:
			// Close the socket so kernel can do other things
			audit_close(fd);
			if (printed == 0)
				printf("No rules\n");
			else {
				lnode *n;
				list_first(&l);
				n = l.cur;
				while (n) {
					print_rule(n->r);
					n = list_next(&l);
				}
				list_clear(&l);
			}
			break;
		case NLMSG_ERROR: 
		        printf("NLMSG_ERROR %d (%s)\n",
				-rep->error->error, 
				strerror(-rep->error->error));
			printed = 1;
			break;
		case AUDIT_GET:
			if (interpret)
				printf("enabled %s\nfailure %s\n",
					get_enable(rep->status->enabled),
					get_failure(rep->status->failure));
			else
				printf("enabled %u\nfailure %u\n",
				rep->status->enabled, rep->status->failure);
			printf("pid %u\nrate_limit %u\nbacklog_limit %u\n"
				"lost %u\nbacklog %u\n",
			rep->status->pid, rep->status->rate_limit,
			rep->status->backlog_limit, rep->status->lost,
			rep->status->backlog);
#if HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME == 1 || \
    HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME == 1

			printf("backlog_wait_time %u\n",
				rep->status->backlog_wait_time);
#endif
			printed = 1;
			break;
#if defined(HAVE_DECL_AUDIT_FEATURE_VERSION) && \
    defined(HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP)
		case AUDIT_GET_FEATURE:
			{
			uint32_t mask = AUDIT_FEATURE_TO_MASK(AUDIT_FEATURE_LOGINUID_IMMUTABLE);
			if (rep->features->mask & mask)
				printf("loginuid_immutable %u %s\n",
					!!(rep->features->features & mask),
					rep->features->lock & mask ? "locked" :
					"unlocked");
			}
			printed = 1;
			break;
#endif
		case AUDIT_LIST_RULES:
			list_requested = 0;
			if (key_match(rep->ruledata))
				 list_append(&l, rep->ruledata,
					sizeof(struct audit_rule_data) +
					rep->ruledata->buflen);
			printed = 1;
			return 1;
		default:
			printf("Unknown: type=%d, len=%d\n", rep->type, 
				rep->nlh->nlmsg_len);
			printed = 1;
			break;
	}
	return 0;
}

