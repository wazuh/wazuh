/*
* ausearch-parse.c - Extract interesting fields and check for match
* Copyright (c) 2005-08,2011,2013-14 Red Hat Inc., Durham, North Carolina.
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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <limits.h>	/* PATH_MAX */
#include <ctype.h>
#include "libaudit.h"
#include "ausearch-options.h"
#include "ausearch-lookup.h"
#include "ausearch-parse.h"
#include "auparse-idata.h"

#define NAME_OFFSET 36
static const char key_sep[2] = { AUDIT_KEY_SEPARATOR, 0 };

static int parse_task_info(lnode *n, search_items *s);
static int parse_syscall(lnode *n, search_items *s);
static int parse_dir(const lnode *n, search_items *s);
static int common_path_parser(search_items *s, char *path);
static int avc_parse_path(const lnode *n, search_items *s);
static int parse_path(const lnode *n, search_items *s);
static int parse_user(const lnode *n, search_items *s);
static int parse_obj(const lnode *n, search_items *s);
static int parse_login(const lnode *n, search_items *s);
static int parse_daemon1(const lnode *n, search_items *s);
static int parse_daemon2(const lnode *n, search_items *s);
static int parse_sockaddr(const lnode *n, search_items *s);
static int parse_avc(const lnode *n, search_items *s);
static int parse_integrity(const lnode *n, search_items *s);
static int parse_kernel_anom(const lnode *n, search_items *s);
static int parse_simple_message(const lnode *n, search_items *s);
static int parse_tty(const lnode *n, search_items *s);
static int parse_pkt(const lnode *n, search_items *s);


static int audit_avc_init(search_items *s)
{
	if (s->avc == NULL) {
		//create
		s->avc = malloc(sizeof(alist));
		if (s->avc == NULL)
			return -1;
		alist_create(s->avc);
	}
	return 0;
}

/*
 * This function will take the list and extract the searchable fields from it.
 * It returns 0 on success and 1 on failure.
 */
int extract_search_items(llist *l)
{
	int ret = 0;
	lnode *n;
	search_items *s = &l->s;
	list_first(l);
	n = list_get_cur(l);
	if (n) {
		do {
			switch (n->type) {
			case AUDIT_SYSCALL:
				ret = parse_syscall(n, s);
				break;
			case AUDIT_CWD:
				ret = parse_dir(n, s);
				break;
			case AUDIT_AVC_PATH:
				ret = avc_parse_path(n, s);
				break;
			case AUDIT_PATH:
				ret = parse_path(n, s);
				break;
			case AUDIT_USER:
			case AUDIT_FIRST_USER_MSG...AUDIT_LAST_USER_MSG:
			case AUDIT_FIRST_USER_MSG2...AUDIT_LAST_USER_MSG2:
				ret = parse_user(n, s);
				break;
			case AUDIT_SOCKADDR:
				ret = parse_sockaddr(n, s);
				break;
			case AUDIT_LOGIN:
				ret = parse_login(n, s);
				break;
			case AUDIT_IPC:
			case AUDIT_OBJ_PID:
				ret = parse_obj(n, s);
				break;
			case AUDIT_DAEMON_START:
			case AUDIT_DAEMON_END:
			case AUDIT_DAEMON_ABORT:
			case AUDIT_DAEMON_CONFIG:
			case AUDIT_DAEMON_ROTATE:
			case AUDIT_DAEMON_RESUME:
				ret = parse_daemon1(n, s);
				break;
			case AUDIT_DAEMON_ACCEPT:
			case AUDIT_DAEMON_CLOSE:
				ret = parse_daemon2(n, s);
				break;
			case AUDIT_CONFIG_CHANGE:
				ret = parse_simple_message(n, s);
				// We use AVC parser because it just looks for
				// the one field. We don't care about return
				// code since older events don't have path=
				avc_parse_path(n, s);
				break;
			case AUDIT_AVC:
				ret = parse_avc(n, s);
				break;
			case AUDIT_NETFILTER_PKT:
				ret = parse_pkt(n, s);
				break;
			case AUDIT_FEATURE_CHANGE:
			case AUDIT_ANOM_LINK:
				ret = parse_task_info(n, s);
				break;
			case AUDIT_SECCOMP:
			case AUDIT_ANOM_PROMISCUOUS:
			case AUDIT_ANOM_ABEND:
		//	   AUDIT_FIRST_KERN_ANOM_MSG...AUDIT_LAST_KERN_ANOM_MSG:
				ret = parse_kernel_anom(n, s);
				break;
			case AUDIT_MAC_POLICY_LOAD...AUDIT_MAC_UNLBL_STCDEL:
				ret = parse_simple_message(n, s);
				break;
			case AUDIT_INTEGRITY_DATA...AUDIT_INTEGRITY_RULE:
				ret = parse_integrity(n, s);
				break;
			case AUDIT_KERNEL:
			case AUDIT_SELINUX_ERR:
			case AUDIT_EXECVE:
			case AUDIT_IPC_SET_PERM:
			case AUDIT_MQ_OPEN:
			case AUDIT_MQ_SENDRECV:
			case AUDIT_MQ_NOTIFY:
			case AUDIT_MQ_GETSETATTR:
			case AUDIT_FD_PAIR:
			case AUDIT_BPRM_FCAPS:
			case AUDIT_CAPSET:
			case AUDIT_MMAP:
			case AUDIT_NETFILTER_CFG:
			case AUDIT_PROCTITLE:
			case AUDIT_KERN_MODULE:
				// Nothing to parse
				break;
			case AUDIT_TTY:
				ret = parse_tty(n, s);
				break;
			default:
				if (event_debug)
					fprintf(stderr,
						"Unparsed type:%d\n - skipped",
						n->type);
				break;
			}
			if (event_debug && ret)
				fprintf(stderr,
					"Malformed event skipped, rc=%d. %s\n",
					 ret, n->message);
		} while ((n=list_next(l)) && ret == 0);
	}
	return ret;
}

/*
 * returns malloc'ed buffer on success and NULL on failure
 */
static const char *lookup_uid(const char *field, uid_t uid)
{
	const char *value;
	value = _auparse_lookup_interpretation(field);
	if (value)
		return value;
	if (uid == 0)
		return strdup("root");
	else if (uid == -1)
		return strdup("unset");
	else {
		struct passwd *pw;
		pw = getpwuid(uid);
		if (pw)
			return strdup(pw->pw_name);
	}
	return NULL;
}

static int parse_task_info(lnode *n, search_items *s)
{
	char *ptr, *str, *term;
	term = n->message;

	// ppid
	if (event_ppid != -1) {
		str = strstr(term, "ppid=");
		if (str != NULL) { // ppid is an optional field
			ptr = str + 5;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 14;
			*term = 0;
			errno = 0;
			s->ppid = strtoul(ptr, NULL, 10);
			if (errno)
				return 15;
			*term = ' ';
		}
	}
	// pid
	if (event_pid != -1) {
		str = strstr(term, " pid=");
		if (str == NULL)
			return 16;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 17;
		*term = 0;
		errno = 0;
		s->pid = strtoul(ptr, NULL, 10);
		if (errno)
			return 18;
		*term = ' ';
	}
	// optionally get loginuid
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(term, "auid=");
		if (str == NULL) {
			str = strstr(term, "loginuid=");
			if (str == NULL)
				return 19;
			ptr = str + 9;
		} else
			ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 20;
		*term = 0;
		errno = 0;
		s->loginuid = strtoul(ptr, NULL, 10);
		if (errno)
			return 21;
		*term = ' ';
		if (s->tauid) free((void *)s->tauid);
		s->tauid = lookup_uid("auid", s->loginuid);
	}
	// optionally get uid
	if (event_uid != -1 || event_tuid) {
try_again:
		str = strstr(term, "uid=");
		if (str == NULL)
			return 22;
		// This sometimes hits auid instead of uid. If so, retry.
		if (*(str-1) == 'a') {
			term = str +1;
			goto try_again;
		}
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 23;
		*term = 0;
		errno = 0;
		s->uid = strtoul(ptr, NULL, 10);
		if (errno)
			return 24;
		*term = ' ';
		if (s->tuid) free((void *)s->tuid);
		s->tuid = lookup_uid("uid", s->uid);
	}

	// optionally get gid
	if (event_gid != -1) {
		str = strstr(term, "gid=");
		if (str == NULL)
			return 25;
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 26;
		*term = 0;
		errno = 0;
		s->gid = strtoul(ptr, NULL, 10);
		if (errno)
			return 27;
		*term = ' ';
	}

	// euid
	if (event_euid != -1 || event_teuid) {
		str = strstr(term, "euid=");
		if (str == NULL)
			return 28;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 29;
		*term = 0;
		errno = 0;
		s->euid = strtoul(ptr, NULL, 10);
		if (errno)
			return 30;
		*term = ' ';
		s->teuid = lookup_uid("euid", s->euid);
	}

	// egid
	if (event_egid != -1) {
		str = strstr(term, "egid=");
		if (str == NULL)
			return 31;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 32;
		*term = 0;
		errno = 0;
		s->egid = strtoul(ptr, NULL, 10);
		if (errno)
			return 33;
		*term = ' ';
	}

	if (event_terminal) {
		// dont do this search unless needed
		str = strstr(term, "tty=");
		if (str) {
			str += 4;
			term = strchr(str, ' ');
			if (term == NULL)
				return 34;
			*term = 0;
			if (s->terminal) // ANOM_NETLINK has one
				free(s->terminal);
			s->terminal = strdup(str);
			*term = ' ';
		}
	}
	// ses
	if (event_session_id != -2 ) {
		str = strstr(term, "ses=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 35;
			*term = 0;
			errno = 0;
			s->session_id = strtoul(ptr, NULL, 10);
			if (errno)
				return 36;
			*term = ' ';
		}
	}

	if (event_comm) {
		// dont do this search unless needed
		str = strstr(term, "comm=");
		if (str) {
			/* Make the syscall one override */
			if (s->comm)
				free(s->comm);
			str += 5;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 37;
				*term = 0;
				s->comm = strdup(str);
				*term = '"';
			} else 
				s->comm = unescape(str);
		} else
			return 38;
	}
	if (event_exe) {
		// dont do this search unless needed
		str = strstr(n->message, "exe=");
		if (str) {
			str += 4;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 39;
				*term = 0;
				if (s->exe) // ANOM_NETLINK has one
					free(s->exe);
				s->exe = strdup(str);
				*term = '"';
			} else 
				s->exe = unescape(str);
		} else
			return 40;
	}
	if (event_subject) {
		// scontext
		str = strstr(term, "subj=");
		if (str != NULL) {
			str += 5;
			term = strchr(str, ' ');
			if (term == NULL)
				return 41;
			*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
				*term = ' ';
			} else
				return 42;
		}
	}
	// success
	if (event_success != S_UNSET) {
		if (term == NULL)
			term = n->message;
		str = strstr(term, "res=");
		if (str != NULL) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term)
				*term = 0;
			errno = 0;
			s->success = strtoul(ptr, NULL, 10);
			if (errno)
				return 43;
			if (term)
				*term = ' ';
		}
	}

	return 0;
}

static int parse_syscall(lnode *n, search_items *s)
{
	char *ptr, *str, *term;
	extern int event_machine;
	int ret;

	term = n->message;
	if (report_format > RPT_DEFAULT || event_machine != -1) {
		// get arch
		str = strstr(term, "arch=");
		if (str == NULL) 
			return 1;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL) 
			return 2;
		*term = 0;
		errno = 0;
		s->arch = (int)strtoul(ptr, NULL, 16);
		if (errno) 
			return 3;
		*term = ' ';
	} 
	// get syscall
	str = strstr(term, "syscall=");
	if (str == NULL)
		return 4;
	ptr = str + 8;
	term = strchr(ptr, ' ');
	if (term == NULL)
		return 5;
	*term = 0;
	errno = 0;
	s->syscall = (int)strtoul(ptr, NULL, 10);
	if (errno)
		return 6;
	*term = ' ';
	// get success
	if (event_success != S_UNSET) {
		str = strstr(term, "success=");
		if (str) { // exit_group does not set success !?!
			ptr = str + 8;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 7;
			*term = 0;
			if (strcmp(ptr, "yes") == 0)
				s->success = S_SUCCESS;
			else
				s->success = S_FAILED;
			*term = ' ';
		}
	}
	// get exit
	if (event_exit_is_set) {
		str = strstr(term, "exit=");
		if (str == NULL)
			return 8;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 9;
		*term = 0;
		errno = 0;
		s->exit = strtoll(ptr, NULL, 0);
		if (errno)
			return 10;
		s->exit_is_set = 1;
		*term = ' ';
	}
	// get a0
	str = strstr(term, "a0=");
	if (str == NULL)
		return 11;
	ptr = str + 3;
	term = strchr(ptr, ' ');
	if (term == NULL)
		return 12;
	*term = 0;
	errno = 0;
	// 64 bit dump on 32 bit machine looks bad here - need long long
	n->a0 = strtoull(ptr, NULL, 16); // Hex
	if (errno)
		return 13;
	*term = ' ';
	// get a1
	str = strstr(term, "a1=");
	if (str == NULL)
		return 11;
	ptr = str + 3;
	term = strchr(ptr, ' ');
	if (term == NULL)
		return 12;
	*term = 0;
	errno = 0;
	// 64 bit dump on 32 bit machine looks bad here - need long long
	n->a1 = strtoull(ptr, NULL, 16); // Hex
	if (errno)
		return 13;
	*term = ' ';

	ret = parse_task_info(n, s);
	if (ret)
		return ret;

	if (event_key) {
		str = strstr(term, "key=");
		if (str) {
			if (!s->key) {
				//create
				s->key = malloc(sizeof(slist));
				if (s->key == NULL)
					return 43;
				slist_create(s->key);
			}
			str += 4;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 44;
				*term = 0;
				if (s->key) {
					// append
					snode sn;
					sn.str = strdup(str);
					sn.key = NULL;
					sn.hits = 1;
					slist_append(s->key, &sn);
				}
				*term = '"';
			} else { 
				if (s->key) {
					char *saved;
					char *keyptr = unescape(str);
					char *kptr = strtok_r(keyptr,
							key_sep, &saved);
					while (kptr) {
						snode sn;
						// append
						sn.str = strdup(kptr);
						sn.key = NULL;
						sn.hits = 1;
						slist_append(s->key, &sn);
						kptr = strtok_r(NULL,
							key_sep, &saved);
					}
					free(keyptr);

				}
			}
		}
	}
	return 0;
}

static int parse_dir(const lnode *n, search_items *s)
{
	char *str, *term;

	if (event_filename) {
	// dont do this search unless needed
		str = strstr(n->message+NAME_OFFSET, " cwd=");
		if (str) {
			str += 5;
			if (*str == '"') {
				/* string is normal */
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 1;
				*term = 0;
				if (!s->cwd) 
					s->cwd = strdup(str);
				*term = '"';
			} else if (!s->cwd) 
				s->cwd = unescape(str);
		}
	}
	return 0;
}

static int common_path_parser(search_items *s, char *path)
{
	char *term;

	if (!s->filename) {
		//create
		s->filename = malloc(sizeof(slist));
		if (s->filename == NULL)
			return 1;
		slist_create(s->filename);
	}
	if (*path == '"') {
		/* string is normal */
		path++;
		term = strchr(path, '"');
		if (term == NULL)
			return 2;
		*term = 0;
		if (s->filename) {
			// append
			snode sn;
			sn.str = strdup(path);
			sn.key = NULL;
			sn.hits = 1;
			// Attempt to rebuild path if relative
			if ((sn.str[0] == '.') && ((sn.str[1] == '.') ||
				(sn.str[1] == '/')) && s->cwd) {
				char *tmp = malloc(PATH_MAX);
				if (tmp == NULL) {
					free(sn.str);
					return 3;
				}
				snprintf(tmp, PATH_MAX,
					"%s/%s", s->cwd, sn.str);
				free(sn.str);
				sn.str = tmp;
			}
			slist_append(s->filename, &sn);
		}
		*term = '"';
	} else { 
		if (s->filename) {
			// append
			snode sn;
			sn.key = NULL;
			sn.hits = 1;
			if (strncmp(path, "(null)", 6) == 0) {
				sn.str = strdup("(null)");
				goto append;
			}
			if (!isxdigit(path[0]))
				return 4;
			if (path[0] == '0' && path[1] == '0')
				sn.str = unescape(&path[2]); // Abstract name
			else {
				term = strchr(path, ' ');
				if (term == NULL)
					return 5;
				*term = 0;
				sn.str = unescape(path);
				*term = ' ';
			}
			// Attempt to rebuild path if relative
			if ((sn.str[0] == '.') && ((sn.str[1] == '.') ||
				(sn.str[1] == '/')) && s->cwd) {
				char *tmp = malloc(PATH_MAX);
				if (tmp == NULL)
					return 6;
				snprintf(tmp, PATH_MAX, "%s/%s", 
					s->cwd, sn.str);
				free(sn.str);
				sn.str = tmp;
			}
append:
			slist_append(s->filename, &sn);
		}
	}
	return 0;
}

/* Older AVCs have path separate from the AVC record */
static int avc_parse_path(const lnode *n, search_items *s)
{
	char *str;

	if (event_filename) {
		// dont do this search unless needed
		str = strstr(n->message, " path=");
		if (str) {
			str += 6;
			return common_path_parser(s, str);
		}
		return 1;
	}
	return 0;
}

static int parse_path(const lnode *n, search_items *s)
{
	// We add 32 to message because we do not need to look at
	// anything before that. Its only time and type.
	char *str, *term = n->message+NAME_OFFSET;

	if (event_filename) {
		// dont do this search unless needed
		str = strstr(term, " name=");
		if (str) {
			int rc;
			str += 6;
			rc = common_path_parser(s, str);
			if (rc)
				return rc;
			term = str;

			// Note that at this point we should be past beginning
			// and around the path element. The type we search for
			// is objtype or nametype. Searching for both will
			// slow us down. So, I'm using what is common to both.
			str = strstr(term, "type=");
			if (str) {
				str += 5;
				s->filename->cur->key = strdup(str);
			}
		}
	}
	if (event_object) {
		// tcontext
		str = strstr(term, "obj=");
		if (str != NULL) {
			str += 4;
			term = strchr(str, ' ');
			if (term)
				*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.tcontext = strdup(str);
				alist_append(s->avc, &an);
				if (term)
					*term = ' ';
			} else
				return 7;
		}
	}
	return 0;
}

static int parse_obj(const lnode *n, search_items *s)
{
	char *str, *term;

	term = n->message;
	if (event_object) {
		// obj context
		str = strstr(term, "obj=");
		if (str != NULL) {
			str += 4;
			term = strchr(str, ' ');
			if (term)
				*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.tcontext = strdup(str);
				alist_append(s->avc, &an);
				if (term)
					*term = ' ';
			} else
				return 1;
		}
	}
	return 0;
}

static int parse_user(const lnode *n, search_items *s)
{
	char *ptr, *str, *term, saved, *mptr;

	term = n->message;

	// get pid
	if (event_pid != -1) {
		str = strstr(term, "pid=");
		if (str == NULL)
			return 1;
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 2;
		*term = 0;
		errno = 0;
		s->pid = strtoul(ptr, NULL, 10);
		if (errno)
			return 3;
		*term = ' ';
	}
	// optionally get uid
	if (event_uid != -1 || event_tuid) {
		str = strstr(term, "uid=");
		if (str == NULL)
			return 4;
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 5;
		*term = 0;
		errno = 0;
		s->uid = strtoul(ptr, NULL, 10);
		if (errno)
			return 6;
		*term = ' ';
		s->tuid = lookup_uid("uid", s->uid);
	}
	// optionally get loginuid
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(term, "auid=");
		if (str == NULL) { // Try the older one
			str = strstr(term, "loginuid=");
			if (str == NULL)
				return 7;
			ptr = str + 9;
		} else
			ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 8;
		*term = 0;
		errno = 0;
		s->loginuid = strtoul(ptr, NULL, 10);
		if (errno)
			return 9;
		*term = ' ';
		s->tauid = lookup_uid("auid", s->loginuid);
	}
	// ses
	if (event_session_id != -2 ) {
		str = strstr(term, "ses=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 10;
			*term = 0;
			errno = 0;
			s->session_id = strtoul(ptr, NULL, 10);
			if (errno)
				return 11;
			*term = ' ';
		}
	}
	if (event_subject) {
		// scontext
		str = strstr(term, "subj=");
		if (str != NULL) {
			str += 5;
			term = strchr(str, ' ');
			if (term == NULL)
				return 12;
			*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
				*term = ' ';
			} else
				return 13;
		}
	}
	// optionally get gid
	if (event_gid != -1) {
		if (n->type == AUDIT_ADD_GROUP || n->type == AUDIT_DEL_GROUP ||
			n->type == AUDIT_GRP_MGMT) {
			str = strstr(term, " id=");
			// Take second shot in the case of MGMT events
			if (str == NULL && n->type == AUDIT_GRP_MGMT)
				str = strstr(term, "gid=");
			if (str) {
				ptr = str + 4;
				term = strchr(ptr, ' ');
				if (term == NULL)
					return 31;
				*term = 0;
				errno = 0;
				s->gid = strtoul(ptr, NULL, 10);
				if (errno)
					return 32;
				*term = ' ';
			}
		}
	}
	if (event_vmname) {
		str = strstr(term, "vm=");
		if (str) {
			str += 3;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 23;
			       *term = 0;
				s->vmname = strdup(str);
				*term = '"';
			} else
				s->vmname = unescape(str);
		}
	}
	if (event_uuid) {
		str = strstr(term, "uuid=");
		if (str) {
			str += 5;
			term = str;
			while (*term != ' ' && *term != ':')
				term++;
			if (term == str)
				return 24;
			saved = *term;
			*term = 0;
			s->uuid = strdup(str);
			*term = saved;
		}
	}
	if (n->type == AUDIT_VIRT_MACHINE_ID) {
		if (event_subject) {
			str = strstr(term, "vm-ctx=");
			if (str != NULL) {
				str += 7;
				term = strchr(str, ' ');
				if (term == NULL)
					return 27;
				*term = 0;
				if (audit_avc_init(s) == 0) {
					anode an;
	
					anode_init(&an);
					an.scontext = strdup(str);
					alist_append(s->avc, &an);
					*term = ' ';
				} else
					return 28;
			}
		}
		if (event_object) {
			str = strstr(term, "img-ctx=");
			if (str != NULL) {
				str += 8;
				term = strchr(str, ' ');
				if (term == NULL)
					return 29;
				*term = 0;
				if (audit_avc_init(s) == 0) {
					anode an;

					anode_init(&an);
					an.tcontext = strdup(str);
					alist_append(s->avc, &an);
					*term = ' ';
				} else
					return 30;
			}
		}
	} else if (n->type == AUDIT_VIRT_RESOURCE) {
		if (event_filename) {
			unsigned int incr = 6;
			str = strstr(term, " path=");
			if (str == NULL) {
				incr = 10;
				str = strstr(term, " new-disk=");
			}
			if (str != NULL) {
				int rc;
				str += incr;
				rc = common_path_parser(s, str);
				if (rc)
					return rc;
				term = str;
			}
		}
	}
	// optionally get uid - some records the second uid is what we want.
	// USER_LOGIN for example.
	if (event_uid != -1 || event_tuid) {
try_again:
		str = strstr(term, "uid=");
		if (str) {
			// If we found auid, skip and try again
			if (*(str - 1) == 'a') {
				term = str +1;
				goto try_again;
			}
			if (*(str - 1) == 's' || *(str - 1) == 'u')
				goto skip;
			if (!(*(str - 1) == '\'' || *(str - 1) == ' '))
				return 25;
			ptr = str + 4;
			term = ptr;
			while (isdigit(*term))
				term++;
			if (term == ptr)
				return 14;

			saved = *term;
			*term = 0;
			errno = 0;
			s->uid = strtoul(ptr, NULL, 10);
			if (errno)
				return 15;
			*term = saved;
			if (s->tuid) free((void *)s->tuid);
			s->tuid = lookup_uid("uid", s->uid);
		}
	}
skip:
	mptr = term + 1;

	if (event_comm) {
		// dont do this search unless needed
		str = strstr(mptr, "comm=");
		if (str) {
			str += 5;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 16;
				*term = 0;
				s->comm = strdup(str);
				*term = '"';
			} else 
				s->comm = unescape(str);
		}
	}

	// Get acct for user/group add/del
	str = strstr(mptr, "acct=");
	if (str != NULL) {
		ptr = str + 5;
		term = ptr + 1;
		if (*ptr == '"') {
			while (*term != '"' && *term)
				term++;
			saved = *term;
			*term = 0;
			ptr++;
			s->acct = strdup(ptr);
			*term = saved;
		} else { 
			/* Handle legacy accts */
			char *end = ptr;
			int legacy = 0;

			while (*end != ' ' && *end) {
				if (!isxdigit(*end))
					legacy = 1;
				end++;
			}
			term = end;
			if (!legacy)
				s->acct = unescape(ptr);
			else {
				saved = *term;
				*term = 0;
				s->acct = strdup(ptr);
				*term = saved;
			}
		}
	}
	mptr = term + 1;

	// get hostname
	if (event_hostname) {
		// dont do this search unless needed
		str = strstr(mptr, "hostname=");
		if (str) {
			str += 9;
			term = strchr(str, ',');
			if (term == NULL) {
				term = strchr(str, ' ');
				if (term == NULL)
					return 17;
			}
			saved = *term;
			*term = 0;
			s->hostname = strdup(str);
			*term = saved;

			// Lets see if there is something more
			// meaningful in addr
			if (strcmp(s->hostname, "?") == 0) {
				term++;
				str = strstr(term, "addr=");
				if (str) {
					str += 5;
					term = strchr(str, ',');
					if (term == NULL) {
						term = strchr(str, ' ');
						if (term == NULL)
							return 18;
					}
					saved = *term;
					*term = 0;
					free(s->hostname);
					s->hostname = strdup(str);
					*term = saved;
				}
			}
		}
	}
	if (event_filename) {
		// dont do this search unless needed
		str = strstr(mptr, "cwd=");
		if (str) {
			str += 4;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 20;
				*term = 0;
				s->cwd = strdup(str);
				*term = '"';
			} else {
				char *end = str;
				int legacy = 0;

				while (*end != ' ') {
					if (!isxdigit(*end)) {
						legacy = 1;
					}
					end++;
				}
				term = end;
				if (!legacy)
					s->cwd = unescape(str);
				else {
					saved = *term;
					*term = 0;
					s->cwd = strdup(str);
					*term = saved;
				}
			}
		}
	}
	if (event_terminal) {
		// dont do this search unless needed
		str = strstr(mptr, "terminal=");
		if (str) {
			str += 9;
			term = strchr(str, ' ');
			if (term == NULL) {
				term = strchr(str, ')');
				if (term == NULL)
					return 19;
			}
			*term = 0;
			s->terminal = strdup(str);
			*term = ' ';
		}
	}
	if (event_exe) {
	// dont do this search unless needed
		str = strstr(mptr, "exe=");
		if (str) {
			str += 4;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 26;
				*term = 0;
				s->exe = strdup(str);
				*term = '"';
			} else {
				char *end = str;
				int legacy = 0;

				while (*end != ' ') {
					if (!isxdigit(*end)) {
						legacy = 1;
					}
					end++;
				}
				term = end;
				if (!legacy)
					s->exe = unescape(str);
				else {
					saved = *term;
					*term = 0;
					s->exe = strdup(str);
					*term = saved;
				}
			}
		}
	}
	
	// get success
	if (event_success != S_UNSET) {
		str = strstr(mptr, "res=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, '\'');
			if (term == NULL)
				return 21;
			*term = 0;
			if (strncmp(ptr, "failed", 6) == 0)
				s->success = S_FAILED;
			else
				s->success = S_SUCCESS;
			*term = '\'';
		} else if ((str = strstr(mptr, "result="))) {
			ptr = str + 7;
			term = strchr(ptr, ')');
			if (term == NULL)
				return 22;
			*term = 0;
			if (strcasecmp(ptr, "success") == 0)
				s->success = S_SUCCESS;
			else
				s->success = S_FAILED;
			*term = ')';
		}
	}
	/* last return code used = 24 */
	return 0;
}

static int parse_login(const lnode *n, search_items *s)
{
	char *ptr, *str, *term = n->message;

	// get pid
	if (event_pid != -1) {
		str = strstr(term, "pid=");
		if (str == NULL)
			return 1;
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 2;
		*term = 0;
		errno = 0;
		s->pid = strtoul(ptr, NULL, 10);
		if (errno)
			return 3;
		*term = ' ';
	}
	// optionally get uid
	if (event_uid != -1 || event_tuid) {
		str = strstr(term, "uid=");
		if (str == NULL)
			return 4;
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 5;
		*term = 0;
		errno = 0;
		s->uid = strtoul(ptr, NULL, 10);
		if (errno)
			return 6;
		*term = ' ';
		s->tuid = lookup_uid("uid", s->uid);
	}
	// optionally get subj
	if (event_subject) {
		str = strstr(term, "subj=");
		if (str) {
			ptr = str + 5;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 12;
			*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
				*term = ' ';
			} else
				return 13;
			*term = ' ';
		}
	}
	// optionally get loginuid
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(term, "new auid=");
		if (str == NULL) {
			// 3.14 kernel changed it to the next line
			str = strstr(term, " auid=");
			if (str == NULL) {
				str = strstr(term, "new loginuid=");
				if (str == NULL)
					return 7;
				ptr = str + 13;
			} else
				ptr = str + 6;
		} else
			ptr = str + 9;
		term = strchr(ptr, ' ');
		if (term)
			*term = 0;
		errno = 0;
		s->loginuid = strtoul(ptr, NULL, 10);
		if (errno)
			return 8;
		if (term)
			*term = ' ';
		s->tauid = lookup_uid("auid", s->loginuid);
	}

	// success
	if (event_success != S_UNSET) {
		if (term == NULL)
			term = n->message;
		str = strstr(term, "res=");
		if (str != NULL) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term)
				*term = 0;
			errno = 0;
			s->success = strtoul(ptr, NULL, 10);
			if (errno)
				return 9;
			if (term)
				*term = ' ';
		} else	// Assume older kernel where always successful
			s->success = S_SUCCESS; 
	}
	// ses
	if (event_session_id != -2 ) {
		if (term == NULL)
			term = n->message;
		str = strstr(term, "new ses=");
		if (str == NULL) {
			// The 3.14 kernel changed it to the next line
			str = strstr(term, " ses=");
			if (str == NULL)
				return 14;
			ptr = str + 5;
		}
		else
			ptr = str + 8;
		term = strchr(ptr, ' ');
		if (term)
			*term = 0;
		errno = 0;
		s->session_id = strtoul(ptr, NULL, 10);
		if (errno)
			return 11;
		if (term)
			*term = ' ';
	}
	return 0;
}

static int parse_daemon1(const lnode *n, search_items *s)
{
	char *ptr, *str, *term, saved, *mptr;

	// Not all messages have a ')', use it if its there
	mptr = strchr(n->message, ')');
	if (mptr == NULL)
		mptr = n->message;
	term = mptr;

	// optionally get auid
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(mptr, "auid=");
		if (str == NULL)
			return 1;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 2;
		saved = *term;
		*term = 0;
		errno = 0;
		s->loginuid = strtoul(ptr, NULL, 10);
		if (errno)
			return 3;
		*term = saved;
		s->tauid = lookup_uid("auid", s->loginuid);
	}

	// pid
	if (event_pid != -1) {
		str = strstr(term, "pid=");
		if (str == NULL)
			return 4;
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL) 
			return 5;
		saved = *term;
		*term = 0;
		errno = 0;
		s->pid = strtoul(ptr, NULL, 10);
		if (errno)
			return 6;
		*term = saved;
	}

	// uid - optional
	if (event_uid != -1) {
		ptr = term;
		str = strstr(term, " uid=");
		if (str) {
			ptr = str + 5;
			term = strchr(ptr, ' ');
			if (term == NULL) 
				return 7;
			saved = *term;
			*term = 0;
			errno = 0;
			s->uid = strtoul(ptr, NULL, 10);
			if (errno)
				return 8;
			*term = saved;
		} else
			term = ptr;
	}

	// ses - optional
	if (event_session_id != -2) {
		ptr = term;
		str = strstr(term, "ses=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL) 
				return 9;
			saved = *term;
			*term = 0;
			errno = 0;
			s->session_id = strtoul(ptr, NULL, 10);
			if (errno)
				return 10;
			*term = saved;
		} else
			term = ptr;
	}

	if (event_subject) {
		// scontext
		str = strstr(term, "subj=");
		if (str != NULL) {
			str += 5;
			term = strchr(str, ' ');
			if (term)
				*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
			} else
				return 11;
			if (term)
				*term = ' ';
		}
	}

	// success
	if (event_success != S_UNSET) {
		str = strstr(mptr, "res=");
		if (str) {
			ptr = term = str + 4;
			while (isalpha(*term))
				term++;
			if (term == ptr)
				return 12;
			saved = *term;
			*term = 0;
			if (strncmp(ptr, "failed", 6) == 0)
				s->success = S_FAILED;
			else
				s->success = S_SUCCESS;
			*term = saved;
		}
	}

	return 0;
}

static int parse_daemon2(const lnode *n, search_items *s)
{
	char *str, saved, *term = n->message;

	if (event_hostname) {
		str = strstr(term, "addr=");
		if (str) {
			str += 5;
			term = strchr(str, ':');
			if (term == NULL) {
				term = strchr(str, ' ');
				if (term == NULL)
					return 1;
			}
			saved = *term;
			*term = 0;
			free(s->hostname);
			s->hostname = strdup(str);
			*term = saved;
		}
	}

	if (event_success != S_UNSET) {
		char *str = strstr(term, "res=");
		if (str) {
			char *ptr, *term, saved;

			ptr = term = str + 4;
			while (isalpha(*term))
				term++;
			if (term == ptr)
				return 2;
			saved = *term;
			*term = 0;
			if (strncmp(ptr, "failed", 6) == 0)
				s->success = S_FAILED;
			else
				s->success = S_SUCCESS;
			*term = saved;
		}
	}

	return 0;
}

static int parse_sockaddr(const lnode *n, search_items *s)
{
	char *str;

	if (event_hostname || event_filename) {
		str = strstr(n->message, "saddr=");
		if (str) {
			int len;
			struct sockaddr *saddr;
			char name[NI_MAXHOST];

			str += 6;
			len = strlen(str)/2;
			s->hostname = unescape(str);
			saddr = (struct sockaddr *)s->hostname;
			if (saddr->sa_family == AF_INET) {
				if (len < sizeof(struct sockaddr_in)) {
					fprintf(stderr,
						"sockaddr len too short\n");
					return 1;
				}
				len = sizeof(struct sockaddr_in);
			} else if (saddr->sa_family == AF_INET6) {
				if (len < sizeof(struct sockaddr_in6)) {
					fprintf(stderr,
						"sockaddr6 len too short\n");
					return 2;
				}
				len = sizeof(struct sockaddr_in6);
			} else if (saddr->sa_family == AF_UNIX) {
				struct sockaddr_un *un =
					(struct sockaddr_un *)saddr;
				if (un->sun_path[0])
					len = strlen(un->sun_path);
				else // abstract name
					len = strlen(&un->sun_path[1]);
				if (len == 0) {
					fprintf(stderr,
						"sun_path len too short\n");
					return 3;
				}
				if (event_filename) {
					if (!s->filename) {
						//create
						s->filename =
							malloc(sizeof(slist));
						if (s->filename == NULL)
							return 4;
						slist_create(s->filename);
					}
					if (s->filename) {
						// append
						snode sn;
						if (un->sun_path[0])
						    sn.str =
							strdup(un->sun_path);
						else
						    sn.str =
							strdup(un->sun_path+1);
						sn.key = NULL;
						sn.hits = 1;
						slist_append(s->filename, &sn);
					}
					free(s->hostname);
					s->hostname = NULL;
					return 0;
				} else { // No file name - no need for socket
					free(s->hostname);
					s->hostname = NULL;
					return 0;
				}
			} else {
				// addr family we don't care about
				free(s->hostname);
				s->hostname = NULL;
				return 0;
			}
			if (!event_hostname) {
				// we entered here for files - discard
				free(s->hostname);
				s->hostname = NULL;
				return 0;
			}
			if (getnameinfo(saddr, len, name, NI_MAXHOST, 
					NULL, 0, NI_NUMERICHOST) ) {
				free(s->hostname);
				s->hostname = NULL;
			} else {
				free(s->hostname);
				s->hostname = strdup(name);
			}
		}
	}
	return 0;
}

static int parse_integrity(const lnode *n, search_items *s)
{
	char *ptr, *str, *term;

	term = n->message;
	// get pid
	str = strstr(term, "pid=");
	if (str) {
		ptr = str + 4;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 1;
		*term = 0;
		errno = 0;
		s->pid = strtoul(ptr, NULL, 10);
		if (errno)
			return 2;
		*term = ' ';
	}

	// optionally get uid
	if (event_uid != -1 || event_tuid) {
		str = strstr(term, " uid=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 3;
			*term = 0;
			errno = 0;
			s->uid = strtoul(ptr, NULL, 10);
			if (errno)
				return 4;
			*term = ' ';
			s->tuid = lookup_uid("uid", s->uid);
		}
	}

	// optionally get loginuid
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(n->message, "auid=");
		if (str) {
			ptr = str + 5;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 5;
			*term = 0;
			errno = 0;
			s->loginuid = strtoul(ptr, NULL, 10);
			if (errno)
				return 6;
			*term = ' ';
			s->tauid = lookup_uid("auid", s->loginuid);
		}
	}

	// ses
	if (event_session_id != -2 ) {
		str = strstr(term, "ses=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 10;
			*term = 0;
			errno = 0;
			s->session_id = strtoul(ptr, NULL, 10);
			if (errno)
				return 11;
			*term = ' ';
		}
	}

	if (event_subject) {
		// scontext
		str = strstr(term, "subj=");
		if (str) {
			str += 5;
			term = strchr(str, ' ');
			if (term == NULL)
				return 12;
			*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
				*term = ' ';
			} else
				return 13;
		}
	}

	if (event_comm) {
		str = strstr(term, "comm=");
		if (str) {
			str += 5;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 7;
				*term = 0;
				s->comm = strdup(str);
				*term = '"';
			} else
				s->comm = unescape(str);
		}
	}

	if (event_filename) {
		str = strstr(term, " name=");
		if (str) {
			str += 6;
			if (common_path_parser(s, str))
				return 8;
		}
	}

	// and results (usually last)
	if (event_success != S_UNSET) {
		str = strstr(term, "res=");
		if (str != NULL) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term)
				*term = 0;
			errno = 0;
			s->success = strtoul(ptr, NULL, 10);
			if (errno)
				return 9;
			if (term)
				*term = ' ';
		}
	}

	return 0;
}


/* FIXME: If they are in permissive mode or hit an auditallow, there can 
 * be more than 1 avc in the same syscall. For now, we pickup just the first.
 */
static int parse_avc(const lnode *n, search_items *s)
{
	char *str, *term;
	anode an;
	int rc=0;

	term = n->message;
	anode_init(&an);

	// get the avc message info.
	str = strstr(term, "avc: ");
	if (str) {
		str += 5;
		term = strchr(str, '{');
		if (term == NULL)
			return 1;
		if (event_success != S_UNSET) {
			*term = 0;
			// FIXME. Do not override syscall success if already
			// set. Syscall pass/fail is the authoritative value.
			if (strstr(str, "denied")) {
				s->success = S_FAILED; 
				an.avc_result = AVC_DENIED;
			} else {
				s->success = S_SUCCESS;
				an.avc_result = AVC_GRANTED;
			}
			*term = '{';
		}

		// Now get permission
		str = term + 1;
		while (*str == ' ')
			str++;
		term = strchr(str, '}');
		if (term == NULL)
			return 2;
		while (*(term-1) == ' ')
			term--;
		*term = 0;
		an.avc_perm = strdup(str);
		*term = ' ';
	}

	// get pid
	if (event_pid != -1) {
		str = strstr(term, "pid=");
		if (str) {
			str = str + 4;
			term = strchr(str, ' ');
			if (term == NULL) {
				rc = 3;
				goto err;
			}
			*term = 0;
			errno = 0;
			s->pid = strtoul(str, NULL, 10);
			if (errno) {
				rc = 4;
				goto err;
			}
			*term = ' ';
		}
	}

	if (event_comm && s->comm == NULL) {
	// dont do this search unless needed
		str = strstr(term, "comm=");
		if (str == NULL) {
			rc = 5;
			goto err;
		}
		str += 5;
		if (*str == '"') {
			str++;
			term = strchr(str, '"');
			if (term == NULL) {
				rc = 6;
				goto err;
			}
			*term = 0;
			s->comm = strdup(str);
			*term = '"';
		} else { 
			s->comm = unescape(str);
			term = str + 6;
		}
	}
	if (event_filename) {
		// do we have a path?
		str = strstr(term, " path=");
		if (str) {
			str += 6;
			rc = common_path_parser(s, str);
			if (rc)
				goto err;
			term += 7;
		} else {
			str = strstr(term, " name=");
			if (str) {
				str += 6;
				rc = common_path_parser(s, str);
				if (rc)
					goto err;
				term += 7;
			}
		}
	}
	if (event_subject) {
		// scontext
		str = strstr(term, "scontext=");
		if (str != NULL) {
			str += 9;
			term = strchr(str, ' ');
			if (term == NULL) {
				rc = 7;
				goto err;
			}
			*term = 0;
			an.scontext = strdup(str);
			*term = ' ';
		}
	}

	if (event_object) {
		// tcontext
		str = strstr(term, "tcontext=");
		if (str != NULL) {
			str += 9;
			term = strchr(str, ' ');
			if (term == NULL) {
				rc = 8;
				goto err;
			}
			*term = 0;
			an.tcontext = strdup(str);
			*term = ' ';
		}
	}

	// Now get the class...its at the end, so we do things different
	str = strstr(term, "tclass=");
	if (str == NULL) {
		rc = 9;
		goto err;
	}
	str += 7;
	term = strchr(str, ' ');
	if (term)
		*term = 0;
	an.avc_class = strdup(str);
	if (term)
		*term = ' ';

	if (audit_avc_init(s) == 0) {
		alist_append(s->avc, &an);
	} else {
		rc = 10;
		goto err;
	}

	return 0;
err:
	anode_clear(&an);
	return rc;
}

static int parse_kernel_anom(const lnode *n, search_items *s)
{
	char *str, *ptr, *term = n->message;

	// optionally get loginuid
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(term, "auid=");
		if (str == NULL)
			return 1;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term)
			*term = 0;
		errno = 0;
		s->loginuid = strtoul(ptr, NULL, 10);
		if (errno)
			return 2;
		if (term)
			*term = ' ';
		else
			term = ptr;
		s->tauid = lookup_uid("auid", s->loginuid);
	}

	// optionally get uid
	if (event_uid != -1 || event_tuid) {
		str = strstr(term, "uid="); // if promiscuous, we start over
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 3;
			*term = 0;
			errno = 0;
			s->uid = strtoul(ptr, NULL, 10);
			if (errno)
				return 4;
			*term = ' ';
			s->tuid = lookup_uid("uid", s->uid);
		}
	}

	// optionally get gid
	if (event_gid != -1) {
		str = strstr(term, "gid=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 5;
			*term = 0;
			errno = 0;
			s->gid = strtoul(ptr, NULL, 10);
			if (errno)
				return 6;
			*term = ' ';
		}
	}

	if (event_session_id != -2) {
		str = strstr(term, "ses=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term)
				*term = 0;
			errno = 0;
			s->session_id = strtoul(ptr, NULL, 10);
			if (errno)
				return 7;
			if (term)
				*term = ' ';
			else
				term = ptr;
		}
	}

	if (n->type == AUDIT_ANOM_PROMISCUOUS)
		return 0; // Nothing else in the event

	if (event_subject) {
		// scontext
		str = strstr(term, "subj=");
		if (str) {
			str += 5;
			term = strchr(str, ' ');
			if (term == NULL)
				return 8;
			*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
				*term = ' ';
			} else
				return 9;
		}
	}

	// get pid
	if (event_pid != -1) {
		str = strstr(term, "pid=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 10;
			*term = 0;
			errno = 0;
			s->pid = strtoul(ptr, NULL, 10);
			if (errno)
				return 11;
			*term = ' ';
		}
	}

	if (event_comm) {
		// dont do this search unless needed
		str = strstr(term, "comm=");
		if (str) {
			str += 5;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 12;
				*term = 0;
				s->comm = strdup(str);
				*term = '"';
			} else 
				s->comm = unescape(str);
		} 
	}

	if (event_exe) {
		// dont do this search unless needed
		str = strstr(term, "exe=");
		if (str) {
			str += 4;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 13;
				*term = 0;
				s->exe = strdup(str);
				*term = '"';
			} else 
				s->exe = unescape(str);
		} else if (n->type != AUDIT_ANOM_ABEND)
			return 14;
	}

	if (n->type == AUDIT_SECCOMP) {
		// get arch
		str = strstr(term, "arch=");
		if (str == NULL) 
			return 0;	// A few kernel versions don't have it
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term == NULL) 
			return 15;
		*term = 0;
		errno = 0;
		s->arch = (int)strtoul(ptr, NULL, 16);
		if (errno) 
			return 16;
		*term = ' ';
		// get syscall
		str = strstr(term, "syscall=");
		if (str == NULL)
			return 17;
		ptr = str + 8;
		term = strchr(ptr, ' ');
		if (term == NULL)
			return 18;
		*term = 0;
		errno = 0;
		s->syscall = (int)strtoul(ptr, NULL, 10);
		if (errno)
			return 19;
		*term = ' ';
	}

	return 0;
}

// This is for messages that only have the loginuid as the item
// of interest.
static int parse_simple_message(const lnode *n, search_items *s)
{
	char *str, *ptr, *term = n->message;

	// optionally get loginuid - old kernels skip auid for CONFIG_CHANGE
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(term, "auid=");
		if (str == NULL && n->type != AUDIT_CONFIG_CHANGE)
			return 1;
		if (str) {
			ptr = str + 5;
			term = strchr(ptr, ' ');
			if (term)
				*term = 0;
			errno = 0;
			s->loginuid = strtoul(ptr, NULL, 10);
			if (errno)
				return 2;
			if (term)
				*term = ' ';
			else
				term = ptr;
			s->tauid = lookup_uid("auid", s->loginuid);
		}
	}

	// ses
	if (event_session_id != -2 ) {
		str = strstr(term, "ses=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term)
				*term = 0;
			errno = 0;
			s->session_id = strtoul(ptr, NULL, 10);
			if (errno)
				return 3;
			if (term)
				*term = ' ';
			else
				term = ptr;
		}
	}

	// Now get subj label
	if (event_subject) {
		// scontext
		str = strstr(term, "subj=");
		if (str != NULL) {
			str += 5;
			term = strchr(str, ' ');
			if (term)
				*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
				if (term)
					*term = ' ';
				else	// Set it back to something sane
					term = str;
			} else
				return 4;
		}
	}

	if (event_key) {
		str = strstr(term, "key=");
		if (str != NULL) {
			if (!s->key) {
				//create
				s->key = malloc(sizeof(slist));
				if (s->key == NULL)
					return 5;
				slist_create(s->key);
			}
			ptr = str + 4;
			if (*ptr == '"') {
				ptr++;
				term = strchr(ptr, '"');
				if (term != NULL) {
					*term = 0;
					if (s->key) {
						// append
						snode sn;
						sn.str = strdup(ptr);
						sn.key = NULL;
						sn.hits = 1;
						slist_append(s->key, &sn);
					}
					*term = '"';
				} else
					return 6;
			} else {
				if (s->key) {
					char *saved;
					char *keyptr = unescape(ptr);
					char *kptr = strtok_r(keyptr,
						key_sep, &saved);
					while (kptr) {
						snode sn;
						// append
						sn.str = strdup(kptr);
						sn.key = NULL;
						sn.hits = 1;
						slist_append(s->key, &sn);
						kptr = strtok_r(NULL,
							key_sep, &saved);
					}
					free(keyptr);
				}
			}
		}
	}

	// defaulting this to 1 for these messages. The kernel generally
	// does not log the res since it can be nothing but success. 
	// But it can still be overriden below if res= is found in the event
	if (n->type == AUDIT_CONFIG_CHANGE) 
		s->success = S_SUCCESS;

	// and results (usually last)
	if (event_success != S_UNSET) {
		str = strstr(term, "res=");
		if (str != NULL) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term)
				*term = 0;
			errno = 0;
			s->success = strtoul(ptr, NULL, 10);
			if (errno)
				return 7;
			if (term)
				*term = ' ';
		}
	}

	return 0;
}

static int parse_tty(const lnode *n, search_items *s)
{
	char *str, *ptr, *term=n->message;

	// get pid
	if (event_pid != -1) {
		str = strstr(n->message, "pid=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 1;
			*term = 0;
			errno = 0;
			s->pid = strtoul(ptr, NULL, 10);
			if (errno)
				return 2;
			*term = ' ';
		}
	}

	// optionally get uid
	if (event_uid != -1 || event_tuid) {
		str = strstr(term, " uid="); // if promiscuous, we start over
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 3;
			*term = 0;
			errno = 0;
			s->uid = strtoul(ptr, NULL, 10);
			if (errno)
				return 4;
			*term = ' ';
			s->tuid = lookup_uid("uid", s->uid);
		}
	}

	// optionally get loginuid
	if (event_loginuid != -2 || event_tauid) {
		str = strstr(term, "auid=");
		if (str == NULL)
			return 5;
		ptr = str + 5;
		term = strchr(ptr, ' ');
		if (term)
			*term = 0;
		errno = 0;
		s->loginuid = strtoul(ptr, NULL, 10);
		if (errno)
			return 6;
		if (term)
			*term = ' ';
		else
			term = ptr;
		s->tauid = lookup_uid("auid", s->loginuid);
	}

	// ses
	if (event_session_id != -2 ) {
		str = strstr(term, "ses=");
		if (str) {
			ptr = str + 4;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 7;
			*term = 0;
			errno = 0;
			s->session_id = strtoul(ptr, NULL, 10);
			if (errno)
				return 8;
			*term = ' ';
		}
	}

/*	if (event_subject) {
		// scontext
		str = strstr(term, "subj=");
		if (str) {
			str += 5;
			term = strchr(str, ' ');
			if (term == NULL)
				return 9;
			*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.scontext = strdup(str);
				alist_append(s->avc, &an);
				*term = ' ';
			} else
				return 10;
		}
	} */

	if (event_comm) {
		// dont do this search unless needed
		str = strstr(term, "comm=");
		if (str) {
			str += 5;
			if (*str == '"') {
				str++;
				term = strchr(str, '"');
				if (term == NULL)
					return 11;
				*term = 0;
				s->comm = strdup(str);
				*term = '"';
			} else 
				s->comm = unescape(str);
		} 
	}

	return 0;
}

static int parse_pkt(const lnode *n, search_items *s)
{
	char *str, *ptr, *term=n->message;

	// get hostname
	if (event_hostname) {
		str = strstr(n->message, "saddr=");
		if (str) {
			ptr = str + 6;
			term = strchr(ptr, ' ');
			if (term == NULL)
				return 1;
			*term = 0;
			s->hostname = strdup(ptr);
			*term = ' ';
		}
	}

	// obj context
	if (event_object) {
		str = strstr(term, "obj=");
		if (str != NULL) {
			str += 4;
			term = strchr(str, ' ');
			if (term)
				*term = 0;
			if (audit_avc_init(s) == 0) {
				anode an;

				anode_init(&an);
				an.tcontext = strdup(str);
				alist_append(s->avc, &an);
				if (term)
					*term = ' ';
			} else
				return 2;
		}
	}

	return 0;
}

