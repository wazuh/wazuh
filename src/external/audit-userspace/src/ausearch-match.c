/*
* ausearch-match.c - Extract interesting fields and check for match
* Copyright (c) 2005-08, 2011 Red Hat Inc., Durham, North Carolina.
* Copyright (c) 2011 IBM Corp.
* All Rights Reserved. 
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
* Boston, MA 02110-1335, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*   Marcelo Henrique Cerri <mhcerri@br.ibm.com>
*/

#include "config.h"
#include <string.h>
#include "libaudit.h"
#include "ausearch-options.h"
#include "ausearch-parse.h"

extern void ausearch_load_interpretations(const lnode *n);

/* local functions */
static int strmatch(const char *needle, const char *haystack);
static int user_match(llist *l);
static int group_match(llist *l);
static int context_match(llist *l);

static void load_interpretations(const llist *l)
{
	// See if there is any reason to load interpretations
	if (event_tuid == NULL && event_teuid == NULL && event_tauid == NULL)
		return;

	// If there is only 1 record load it, or load just the syscall one
	if ((l->cnt == 1) || (l->head && l->head->type == AUDIT_SYSCALL))
		ausearch_load_interpretations(l->head);
}

/*
 * This function performs that matching of search params with the record.
 * It returns 1 on a match, and 0 if no match. The way that this function
 * works is that it will try to determine if there is not a match and exit
 * as soon as possible. We can do this since all command line params form
 * an 'and' statement. If anything does not match, no need to evaluate the
 * rest of the params.
 */
#include <stdio.h>
int match(llist *l)
{
	// Are we within time range?
	if (start_time == 0 || l->e.sec >= start_time) {
		if (end_time == 0 || l->e.sec <= end_time) {
			if (event_id == -1 || event_id == l->e.serial) {
				// Load interpretations if needed
				load_interpretations(l);

				// OK - do the heavier checking
				if (extract_search_items(l)) {
					return 0;
				}

				// perform additional tests for the field
				if (event_node_list) {
					const snode *sn;
					int found=0;
					slist *sptr = event_node_list;

					if (l->e.node == NULL)
				  		return 0;

					slist_first(sptr);
					sn=slist_get_cur(sptr);
					while (sn && !found) {
						if (sn->str &&
						  (!strcmp(sn->str, l->e.node)))
							found++;
						else
							sn=slist_next(sptr);
					}
					if (!found)
						return 0;
				}
				if (user_match(l) == 0)
					return 0;
				if (group_match(l) == 0)
					return 0;
				if ((event_ppid != -1) && 
						(event_ppid != l->s.ppid))
					return 0;
				if ((event_pid != -1) && 
						(event_pid != l->s.pid))
					return 0;
				if (event_machine != -1 && 
						(event_machine !=
					audit_elf_to_machine(l->s.arch)))
					return 0;
				if ((event_syscall != -1) && 
					(event_syscall != l->s.syscall))
						return 0;
				if ((event_session_id != -2) &&
					(event_session_id != l->s.session_id))
					return 0;
				if (event_exit_is_set) {
					if (l->s.exit_is_set == 0)
						return 0;
					if (event_exit != l->s.exit)
						return 0;
				}

				if ((event_success != S_UNSET) &&
						(event_success != l->s.success))
					return 0;
				// event_type requires looking at each item
				if (event_type != NULL) {
					int found = 0;
					const lnode *n;

					list_first(l);
					n = list_get_cur(l);
					do {
						int_node *in;
						ilist_first(event_type);
						in = ilist_get_cur(event_type);
						do {
							if (in->num == n->type){
								found = 1;
								break;
							}
						} while((in = 
						    ilist_next(event_type)));
						if (found)
							break;
					} while ((n = list_next(l)));
					if (!found)
						return 0;
				}

				// Done all the easy compares, now do the 
				// string searches.
				if (event_filename) {
					int found = 0;
					if (l->s.filename == NULL && l->s.cwd == NULL)
						return 0;
					if (l->s.filename) {
						const snode *sn;
						slist *sptr = l->s.filename;

						slist_first(sptr);
						sn=slist_get_cur(sptr);
						do {
							if (sn->str == NULL)
								return 0;
							if (strmatch(
								event_filename,
								sn->str)) {
								found = 1;
								break;
							}
						} while ((sn=slist_next(sptr)));

						if (!found && l->s.cwd == NULL)
							return 0;
					}
					if (l->s.cwd && !found) {
						/* Check cwd, too */
						if (strmatch(event_filename,
								l->s.cwd) == 0)
							return 0;
					}
				}
				if (event_hostname) {
					if (l->s.hostname == NULL)
						return 0;
					if (strmatch(event_hostname, 
						l->s.hostname) == 0)
						return 0; 
				}
				if (event_terminal) {
					if (l->s.terminal == NULL)
						return 0;
					if (strmatch(event_terminal, 
						l->s.terminal) == 0)
						return 0; 
				}
				if (event_exe) {
					if (l->s.exe == NULL)
						return 0;
					if (strmatch(event_exe, 
						l->s.exe) == 0)
						return 0; 
				}				
				if (event_comm) {
					if (l->s.comm == NULL)
						return 0;
					if (strmatch(event_comm, 
						l->s.comm) == 0)
						return 0; 
				}				
				if (event_key) {
					if (l->s.key == NULL)
						return 0;
					else {
						int found = 0;
						const snode *sn;
						slist *sptr = l->s.key;

						slist_first(sptr);
						sn=slist_get_cur(sptr);
						do {
							if (sn->str == NULL)
								return 0;
							if (strmatch(
								event_key,
								sn->str)) {
								found = 1;
								break;
							}
						} while ((sn=slist_next(sptr)));
						if (!found)
							return 0;
					}
				}				
				if (event_vmname) {
					if (l->s.vmname == NULL)
						return 0;
					if (strmatch(event_vmname,
							l->s.vmname) == 0)
						return 0;
				}
				if (event_uuid) {
					if (l->s.uuid == NULL)
						return 0;
					if (strmatch(event_uuid,
							l->s.uuid) == 0)
						return 0;
				}
				if (context_match(l) == 0)
					return 0;
				return 1;
			}
		}
	}
	return 0;
}

/*
 * This function compares strings. It returns a 0 if no match and a 1 if
 * there is a match 
 */
static int strmatch(const char *needle, const char *haystack)
{
	if (event_exact_match) {
		if (strcmp(haystack, needle) != 0)
			return 0; 
	} else {
		if (strstr(haystack, needle) == NULL)
			return 0; 
	}
	return 1;
}

/*
 * This function compares user id's.
 * It returns a 0 if no match and a 1 if there is a match 
 */
static int user_match(llist *l)
{
	// Match by string if set (assume all event vars are set)
	if (event_ua && event_tuid) {
		// This will "or" the user tests
		if (l->s.tuid && strcmp(event_tuid, l->s.tuid) == 0)
			return 1;
		if (l->s.teuid && strcmp(event_teuid, l->s.teuid) == 0)
			return 1;
		if (l->s.tauid && strcmp(event_tauid, l->s.tauid) == 0)
			return 1;
		return 0;
	// OK, try a pure numeric match
	} else if (event_ua) {
		// This will "or" the user tests
		if (event_uid == l->s.uid)
			return 1;
		if (event_euid == l->s.euid)
			return 1;
		if (event_loginuid == l->s.loginuid)
			return 1;
		return 0;
	} else {
		// This will "and" the user tests
		if (event_tuid || event_teuid || event_tauid) {
			if (event_tuid) {
				if (l->s.tuid == NULL)
					return 0;
				if (strcmp(event_tuid, l->s.tuid))
					return 0;
			}
			if (event_teuid) {
				if (l->s.teuid == NULL)
					return 0;
				if (strcmp(event_teuid, l->s.teuid))
					return 0;
			}
			if (event_tauid) {
				if (l->s.tauid == NULL)
					return 0;
				if (strcmp(event_tauid, l->s.tauid))
					return 0;
			}
		} else {
			// Numeric only match
			if ((event_uid != -1) && (event_uid != l->s.uid))
				return 0;
			if ((event_euid != -1) &&(event_euid != l->s.euid))
				return 0;
			if ((event_loginuid != -2) &&
					(event_loginuid != l->s.loginuid))
				return 0;
		}
	}
	return 1;
}

/*
 * This function compares group id's. It returns a 0 if no match and a 1 if
 * there is a match 
 */
static int group_match(llist *l)
{
	if (event_ga) {
		// This will "or" the group tests
		if (event_gid == l->s.gid)
			return 1;
		if (event_egid == l->s.egid)
			return 1;
		return 0;
	} else {
		// This will "and" the group tests
		if ((event_gid != -1) && (event_gid != l->s.gid))
			return 0;
		if ((event_egid != -1) &&(event_egid != l->s.egid))
			return 0;
	}
	return 1;
}

/*
 * This function compares contexts. It returns a 0 if no match and a 1 if
 * there is a match 
 */
static int context_match(llist *l)
{
	if (event_se) { /* This does the "or" check if -se test */
		if (event_subject) {
			if (l->s.avc && alist_find_subj(l->s.avc)) {
				do {
					if (strmatch(event_subject, 
						l->s.avc->cur->scontext))
						return 1;
				} while(alist_next_subj(l->s.avc));
			}
		} 
		if (event_object) {
			if (l->s.avc) {
				alist_first(l->s.avc);
				if (alist_find_obj(l->s.avc)) {
					do {
						if (strmatch(event_object, 
						    l->s.avc->cur->tcontext))
						    return 1;
	 				} while(alist_next_obj(l->s.avc));
				}
			}
		}
		return 0;
	} else {
		if (event_subject) {
			if (l->s.avc == NULL)
				return 0;
			if (alist_find_subj(l->s.avc)) {
				do {
					if (strmatch(event_subject, 
						l->s.avc->cur->scontext))
						return 1;
				} while(alist_next_subj(l->s.avc));
			}
			return 0;
		} 
		if (event_object) {
			if (l->s.avc == NULL)
				return 0;
			if (alist_find_obj(l->s.avc)) {
				do {
					if (strmatch(event_object, 
						l->s.avc->cur->tcontext))
						return 1;
				} while(alist_next_obj(l->s.avc));
			}
			return 0;
		}
	}
	return 1;
}

