/*
* interpret.c - Lookup values to something more readable
* Copyright (c) 2007-09,2011-16 Red Hat Inc., Durham, North Carolina.
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

#include "config.h"
#include "lru.h"
#include "libaudit.h"
#include "internal.h"
#include "interpret.h"
#include "auparse-idata.h"
#include "nvlist.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <linux/net.h>
#include <netdb.h>
#include <sys/un.h>
#include <linux/ax25.h>
#include <linux/atm.h>
#include <linux/x25.h>
#include <linux/if.h>   // FIXME: remove when ipx.h is fixed
#include <linux/ipx.h>
#include <linux/capability.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sched.h>
#ifdef USE_FANOTIFY
#include <linux/fanotify.h>
#else
#define FAN_ALLOW 1
#define FAN_DENY 2
#endif
#include "auparse-defs.h"
#include "gen_tables.h"

#if !HAVE_DECL_ADDR_NO_RANDOMIZE
# define ADDR_NO_RANDOMIZE       0x0040000
#endif

/* This is from asm/ipc.h. Copying it for now as some platforms
 * have broken headers. */
#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define SEMTIMEDOP	 4
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24
#define DIPC            25

#include "captabs.h"
#include "clone-flagtabs.h"
#include "epoll_ctls.h"
#include "famtabs.h"
#include "fcntl-cmdtabs.h"
#include "flagtabs.h"
#include "ipctabs.h"
#include "ipccmdtabs.h"
#include "mmaptabs.h"
#include "mounttabs.h"
#include "open-flagtabs.h"
#include "persontabs.h"
#include "prottabs.h"
#include "ptracetabs.h"
#include "recvtabs.h"
#include "rlimittabs.h"
#include "seektabs.h"
#include "socktabs.h"
#include "socktypetabs.h"
#include "signaltabs.h"
#include "clocktabs.h"
#include "typetabs.h"
#include "nfprototabs.h"
#include "icmptypetabs.h"
#include "seccomptabs.h"
#include "accesstabs.h"
#include "prctl_opttabs.h"
#include "schedtabs.h"
#include "shm_modetabs.h"
#include "sockoptnametabs.h"
#include "sockleveltabs.h"
#include "ipoptnametabs.h"
#include "ip6optnametabs.h"
#include "tcpoptnametabs.h"
#include "pktoptnametabs.h"
#include "umounttabs.h"
#include "ioctlreqtabs.h"
#include "inethooktabs.h"
#include "netactiontabs.h"

typedef enum { AVC_UNSET, AVC_DENIED, AVC_GRANTED } avc_t;
typedef enum { S_UNSET=-1, S_FAILED, S_SUCCESS } success_t;

static char *print_escaped(const char *val);
static const char *print_signals(const char *val, unsigned int base);

// FIXME: move next declaration to auparse_state_t
static nvlist il;  // Interpretations list

/*
 * This function will take a pointer to a 2 byte Ascii character buffer and
 * return the actual hex value.
 */
static unsigned char x2c(const unsigned char *buf)
{
        static const char AsciiArray[17] = "0123456789ABCDEF";
        char *ptr;
        unsigned char total=0;

        ptr = strchr(AsciiArray, (char)toupper(buf[0]));
        if (ptr)
                total = (unsigned char)(((ptr-AsciiArray) & 0x0F)<<4);
        ptr = strchr(AsciiArray, (char)toupper(buf[1]));
        if (ptr)
                total += (unsigned char)((ptr-AsciiArray) & 0x0F);

        return total;
}

// Check if any characters need tty escaping. Returns how many found.
static unsigned int need_tty_escape(const unsigned char *s, unsigned int len)
{
	unsigned int i = 0, cnt = 0;
	while (i < len) {
		if (s[i] < 32)
			cnt++;
		i++;
	}
	return cnt;
}

// TTY escaping s string into dest.
static void tty_escape(const char *s, char *dest, unsigned int len)
{
	unsigned int i = 0, j = 0;
	while (i < len) {
		if ((unsigned char)s[i] < 32) {
			dest[j++] = ('\\');
			dest[j++] = ('0' + ((s[i] & 0300) >> 6));
			dest[j++] = ('0' + ((s[i] & 0070) >> 3));
			dest[j++] = ('0' + (s[i] & 0007));
		} else
			dest[j++] = s[i];
		i++;
	}
	dest[j] = '\0';	/* terminate string */
}

static const char sh_set[] = "\"'`$\\!()| ";
static unsigned int need_shell_escape(const char *s, unsigned int len)
{
	unsigned int i = 0, cnt = 0;
	while (i < len) {
		if (s[i] < 32)
			cnt++;
		else if (strchr(sh_set, s[i]))
			cnt++;
		i++;
	}
	return cnt;
}

static void shell_escape(const char *s, char *dest, unsigned int len)
{
	unsigned int i = 0, j = 0;
	while (i < len) {
		if ((unsigned char)s[i] < 32) {
			dest[j++] = ('\\');
			dest[j++] = ('0' + ((s[i] & 0300) >> 6));
			dest[j++] = ('0' + ((s[i] & 0070) >> 3));
			dest[j++] = ('0' + (s[i] & 0007));
		} else if (strchr(sh_set, s[i])) {
			dest[j++] = ('\\');
			dest[j++] = s[i];
		} else
			dest[j++] = s[i];
		i++;
	}
	dest[j] = '\0';	/* terminate string */
}
                                
static const char quote_set[] = "\"'`$\\!()| ;#&*?[]<>{}";
static unsigned int need_shell_quote_escape(const unsigned char *s, unsigned int len)
{
	unsigned int i = 0, cnt = 0;
	while (i < len) {
		if (s[i] < 32)
			cnt++;
		else if (strchr(quote_set, s[i]))
			cnt++;
		i++;
	}
	return cnt;
}

static void shell_quote_escape(const char *s, char *dest, unsigned int len)
{
	unsigned int i = 0, j = 0;
	while (i < len) {
		if ((unsigned char)s[i] < 32) {
			dest[j++] = ('\\');
			dest[j++] = ('0' + ((s[i] & 0300) >> 6));
			dest[j++] = ('0' + ((s[i] & 0070) >> 3));
			dest[j++] = ('0' + (s[i] & 0007));
		} else if (strchr(quote_set, s[i])) {
			dest[j++] = ('\\');
			dest[j++] = s[i];
		} else
			dest[j++] = s[i];
		i++;
	}
	dest[j] = '\0';	/* terminate string */
}

/* This should return the count of what needs escaping */
static unsigned int need_escaping(const char *s, unsigned int len,
	auparse_esc_t escape_mode)
{
	switch (escape_mode)
	{
		case AUPARSE_ESC_RAW:
			break;
		case AUPARSE_ESC_TTY:
			return need_tty_escape(s, len);
		case AUPARSE_ESC_SHELL:
			return need_shell_escape(s, len);
		case AUPARSE_ESC_SHELL_QUOTE:
			return need_shell_quote_escape(s, len);
	}
	return 0;
}

static void escape(const char *s, char *dest, unsigned int len,
	auparse_esc_t escape_mode)
{
	switch (escape_mode)
	{
		case AUPARSE_ESC_RAW:
			return;
		case AUPARSE_ESC_TTY:
			return tty_escape(s, dest, len);
		case AUPARSE_ESC_SHELL:
			return shell_escape(s, dest, len);
		case AUPARSE_ESC_SHELL_QUOTE:
			return shell_quote_escape(s, dest, len);
	}
}

static void key_escape(char *orig, char *dest, auparse_esc_t escape_mode)
{
	const char *optr = orig;
	char *str, *dptr = dest, tmp;
	while (*optr) {
		unsigned int klen, cnt;
		// Find the separator or the end
		str = strchr(optr, AUDIT_KEY_SEPARATOR);
		if (str == NULL)
			str = strchr(optr, 0);
		klen = str - optr;
		tmp = *str;
		*str = 0;
		cnt = need_escaping(optr, klen, escape_mode);
		if (cnt == 0)
			dptr = stpcpy(dptr, optr);
		else {
			escape(optr, dptr, klen, escape_mode);
			dptr = strchr(dest, 0);
			if (dptr == NULL)
				return; // Something is really messed up
		}
		// Put the separator back
		*str = tmp;
		*dptr = tmp;
		optr = str;
		// If we are not at the end...
		if (tmp) {
			optr++;
			dptr++;
		}
	}
}

static int is_hex_string(const char *str)
{
	while (*str) {
		if (!isxdigit(*str))
			return 0;
		str++;
	}
	return 1;
}

/* returns a freshly malloc'ed and converted buffer */
char *au_unescape(char *buf)
{
        int olen, len, i;
        char saved, *str, *ptr = buf;

        /* Find the end of the name */
        if (*ptr == '(') {
                ptr = strchr(ptr, ')');
                if (ptr == NULL)
                        return NULL;
                else
                        ptr++;
        } else {
                while (isxdigit(*ptr))
                        ptr++;
        }
	// Make the buffer based on size of original buffer.
	// This is in case we have unexpected non-hex digit
	// that causes truncation of the conversion and passes
	// back a buffer that is not sized on the expectation of
	// strlen(buf) / 2.
	olen = strlen(buf);
	str = malloc(olen+1);

        saved = *ptr;
        *ptr = 0;
	strcpy(str, buf);
        *ptr = saved;

	/* See if its '(null)' from the kernel */
        if (*buf == '(')
                return str;

        /* We can get away with this since the buffer is 2 times
         * bigger than what we are putting there.
         */
        len = strlen(str);
        if (len < 2) {
                free(str);
                return NULL;
        }
        ptr = str;
        for (i=0; i<len; i+=2) {
                *ptr = x2c((unsigned char *)&str[i]);
                ptr++;
        }
        *ptr = 0;
	len = ptr - str - 1;
	olen /= 2;
	// Because *ptr is 0, writing another 0 to it doesn't hurt anything
	if (olen > len)
		memset(ptr, 0, olen - len);
        return str;
}

/////////// Interpretation list functions ///////////////
void init_interpretation_list(void)
{
	nvlist_create(&il);
}

/*
 * Returns 0 on error and 1 on success
 */
int load_interpretation_list(const char *buffer)
{
	char *saved = NULL, *ptr;
	char *buf, *val;
	nvnode n;

	if (buffer == NULL)
		return 0;

	buf = strdup(buffer);
	if (strncmp(buf, "SADDR=", 6) == 0) {
		// We have SOCKADDR record. It has no other values.
		// Handle it by itself.
		ptr = strchr(buf+6, '{');
		if (ptr) {
			val = ptr;
			ptr = strchr(val, '}');
			if (ptr) {
				n.name = strdup("saddr");
				n.val = strdup(val);
				nvlist_append(&il, &n);
				nvlist_interp_fixup(&il);
				free(buf);
				return 1;
			}
		}
		free(buf);
		return 0;
	} else {
		// We handle everything else in this branch
		ptr = audit_strsplit_r(buf, &saved);
		if (ptr == NULL) {
			free(buf);
			return 0;
		}

		do {
			char tmp;

			val = strchr(ptr, '=');
			if (val) {
				*val = 0;
				val++;
			} else	// Malformed - skip
				continue;
			n.name = strdup(ptr);
			char *c = n.name;
			while (*c) {
				*c = tolower(*c);
				c++;
			}
			ptr = strchr(val, ' ');
			if (ptr) {
				tmp = *ptr;
				*ptr = 0;
			} else
				tmp = 0;

			n.val = strdup(val);
			nvlist_append(&il, &n);
			nvlist_interp_fixup(&il);
			if (ptr)
				*ptr = tmp;
		} while((ptr = audit_strsplit_r(NULL, &saved)));
	}
	free(buf);
	return 1;
}

/*
 * Returns malloc'ed buffer on success and NULL if no match
 */
const char *_auparse_lookup_interpretation(const char *name)
{
	nvnode *n;

	nvlist_first(&il);
	if (nvlist_find_name(&il, name)) {
		n = nvlist_get_cur(&il);
		// This is only called from src/ausearch-lookup.c
		// it only looks up auid and syscall. One needs
		// escape, the other does not.
		if (strstr(name, "id"))
			return print_escaped(n->interp_val);
		else
			return strdup(n->interp_val);
	}
	return NULL;
}

void free_interpretation_list(void)
{
	nvlist_clear(&il);
}

//////////// Start Field Value Interpretations /////////////

static const char *success[3]= { "unset", "no", "yes" };
static const char *aulookup_success(int s)
{
	switch (s)
	{
		default:
			return success[0];
			break;
		case S_FAILED:
			return success[1];
			break;
		case S_SUCCESS:
			return success[2];
			break;
	}
}

static Queue *uid_cache = NULL;
static int uid_cache_created = 0;
static const char *aulookup_uid(uid_t uid, char *buf, size_t size)
{
	char *name = NULL;
	unsigned int key;
	QNode *q_node;

	if (uid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	} else if (uid == 0) {
		snprintf(buf, size, "root");
		return buf;
	}

	// Check the cache first
	if (uid_cache_created == 0) {
		uid_cache = init_lru(19, NULL, "uid");
		uid_cache_created = 1;
	}
	key = compute_subject_key(uid_cache, uid);
	q_node = check_lru_cache(uid_cache, key);
	if (q_node) {
		if (q_node->id == uid)
			name = q_node->str;
		else {
			// This getpw use is OK because its for protocol 1
			// compatibility.  Add it to cache.
			struct passwd *pw;
			lru_evict(uid_cache, key);
			q_node = check_lru_cache(uid_cache, key);
			pw = getpwuid(uid);
			if (pw) {
				q_node->str = strdup(pw->pw_name);
				q_node->id = uid;
				name = q_node->str;
			}
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", uid);
	return buf;
}

void aulookup_destroy_uid_list(void)
{
	if (uid_cache_created == 0)
		return;

	destroy_lru(uid_cache); 
	uid_cache_created = 0;
}

static Queue *gid_cache = NULL;
static int gid_cache_created = 0;
static const char *aulookup_gid(gid_t gid, char *buf, size_t size)
{
	char *name = NULL;
	unsigned int key;
	QNode *q_node;

	if (gid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	} else if (gid == 0) {
		snprintf(buf, size, "root");
		return buf;
	}

	// Check the cache first
	if (gid_cache_created == 0) {
		gid_cache = init_lru(19, NULL, "gid");
		gid_cache_created = 1;
	}
	key = compute_subject_key(gid_cache, gid);
	q_node = check_lru_cache(gid_cache, key);
	if (q_node) {
		if (q_node->id == gid)
			name = q_node->str;
		else {
			// Add it to cache
			struct group *gr;
			lru_evict(gid_cache, key);
			q_node = check_lru_cache(gid_cache, key);
			gr = getgrgid(gid);
			if (gr) {
				q_node->str = strdup(gr->gr_name);
				q_node->id = gid;
				name = q_node->str;
			}
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", gid);
	return buf;
}

void aulookup_destroy_gid_list(void)
{
	if (gid_cache_created == 0)
		return;

	destroy_lru(gid_cache); 
	gid_cache_created = 0;
}

static const char *print_uid(const char *val, unsigned int base)
{
        int uid;
        char name[64];

        errno = 0;
        uid = strtoul(val, NULL, base);
        if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

        return strdup(aulookup_uid(uid, name, sizeof(name)));
}

static const char *print_gid(const char *val, unsigned int base)
{
        int gid;
        char name[64];

        errno = 0;
        gid = strtoul(val, NULL, base);
        if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

        return strdup(aulookup_gid(gid, name, sizeof(name)));
}

static const char *print_arch(const char *val, unsigned int machine)
{
        const char *ptr;
	char *out;

	if (machine > MACH_AARCH64) {
		unsigned int ival;

		errno = 0;
		ival = strtoul(val, NULL, 16);
		if (errno) {
			if (asprintf(&out, "conversion error(%s) ", val) < 0)
				out = NULL;
			return out;
		}
		machine = audit_elf_to_machine(ival);
	}
        if ((int)machine < 0) {
		if (asprintf(&out, "unknown-elf-type(%s)", val) < 0)
			out = NULL;
                return out;
        }
        ptr = audit_machine_to_name(machine);
	if (ptr)
	        return strdup(ptr);
	else {
		if (asprintf(&out, "unknown-machine-type(%d)", machine) < 0)
			out = NULL;
                return out;
	}
}

static const char *print_ipccall(const char *val, unsigned int base)
{
	int a0;
	char *out;
	const char *func = NULL;

	errno = 0;
	a0 = strtol(val, NULL, base);
	if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	func = ipc_i2s(a0);
	if (func)
		return strdup(func);
	else {
		if (asprintf(&out, "unknown-ipccall(%s)", val) < 0)
			out = NULL;
                return out;
	}
}

static const char *print_socketcall(const char *val, unsigned int base)
{
	int a0;
	char *out;
	const char *func = NULL;

	errno = 0;
	a0 = strtol(val, NULL, base);
	if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	func = sock_i2s(a0);
	if (func)
		return strdup(func);
	else {
		if (asprintf(&out, "unknown-socketcall(%s)", val) < 0)
			out = NULL;
                return out;
	}
}

static const char *print_syscall(const idata *id)
{
	const char *sys;
	char *out;
	int machine = id->machine, syscall = id->syscall;
	unsigned long long a0 = id->a0;

        if (machine < 0)
                machine = audit_detect_machine();
        if (machine < 0) {
                out = strdup(id->val);
                return out;
        }
        sys = audit_syscall_to_name(syscall, machine);
        if (sys) {
                const char *func = NULL;
                if (strcmp(sys, "socketcall") == 0) {
			if ((int)a0 == a0)
				func = sock_i2s(a0);
                } else if (strcmp(sys, "ipc") == 0)
			if ((int)a0 == a0)
				func = ipc_i2s(a0);
                if (func) {
			if (asprintf(&out, "%s(%s)", sys, func) < 0)
				out = NULL;
		} else
                        return strdup(sys);
        } else {
		if (asprintf(&out, "unknown-syscall(%d)", syscall) < 0)
			out = NULL;
	}

	return out;
}

static const char *print_exit(const char *val)
{
        long long ival;
        char *out;

        errno = 0;
        ival = strtoll(val, NULL, 10);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

        if (ival < 0) {
		if (asprintf(&out, "%s(%s)", audit_errno_to_name(-ival),
					strerror(-ival)) < 0)
			out = NULL;
		return out;
        }
        return strdup(val);
}

static char *print_escaped(const char *val)
{
	char *out;

        if (*val == '"') {
                char *term;
                val++;
                term = strchr(val, '"');
                if (term == NULL)
                        return strdup(" ");
                *term = 0;
                out = strdup(val);
		*term = '"';
		return out;
// FIXME: working here...was trying to detect (null) and handle that
// differently. The other 2 should have " around the file names.
/*      } else if (*val == '(') {
                char *term;
                val++;
                term = strchr(val, ' ');
                if (term == NULL)
                        return;
                *term = 0;
                printf("%s ", val); */
        } else if (val[0] == '0' && val[1] == '0')
                out = au_unescape((char *)&val[2]); // Abstract name af_unix
	else
                out = au_unescape((char *)val);
	if (out)
		return out;
	return strdup(val); // Something is wrong with string, just send as is
}

static const char *print_escaped_ext(const idata *id)
{
	if (id->cwd) {
		char *str1 = NULL, *str2, *str3 = NULL, *out = NULL;
		str2 = print_escaped(id->val);
		if (!str2)
			goto err_out;
		if (*str2 != '/') {
			str1 = print_escaped(id->cwd);
			if (!str1)
				goto err_out;
			if (asprintf(&str3, "%s/%s", str1, str2) < 0)
				goto err_out;
		} else {
			// Check in case /home/../etc/passwd
			if (strstr(str2, "..") == NULL)
				return str2;

			str3 = str2;
			str2 = NULL;
			str1 = NULL;
		}
		errno = 0;
		out = realpath(str3, NULL);
		if (errno) { // If there's an error, just return the original
			free(str1);
			free(str2);
			return str3;
		}
err_out:
		free(str1);
		free(str2);
		free(str3);
		return out;
	} else
		return print_escaped(id->val);
}

static const char *print_proctitle(const char *val)
{
	char *out = (char *)print_escaped(val);
	if (*val != '"') {
		size_t len = strlen(val) / 2;
		const char *end = out + len;
		char *ptr = out;
		// Proctitle has arguments separated by NUL bytes
		// We need to write over the NUL bytes with a space
		// so that we can see the arguments
		while ((ptr  = rawmemchr(ptr, '\0'))) {
			if (ptr >= end)
				break;
			*ptr = ' ';
			ptr++;
		}
	}
	return out;
}

static const char *print_perm(const char *val)
{
        int ival, printed=0;
	char buf[32];

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	buf[0] = 0;

        /* The kernel treats nothing (0x00) as everything (0x0F) */
        if (ival == 0)
                ival = 0x0F;
        if (ival & AUDIT_PERM_READ) {
                strcat(buf, "read");
                printed = 1;
        }
        if (ival & AUDIT_PERM_WRITE) {
                if (printed)
                        strcat(buf, ",write");
                else
                        strcat(buf, "write");
                printed = 1;
        }
        if (ival & AUDIT_PERM_EXEC) {
                if (printed)
                        strcat(buf, ",exec");
                else
                        strcat(buf, "exec");
                printed = 1;
        }
        if (ival & AUDIT_PERM_ATTR) {
                if (printed)
                        strcat(buf, ",attr");
                else
                        strcat(buf, "attr");
        }
	return strdup(buf);
}

static const char *print_mode(const char *val, unsigned int base)
{
        unsigned int ival;
	char *out, buf[48];
	const char *name;

        errno = 0;
        ival = strtoul(val, NULL, base);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

        // detect the file type
	name = audit_ftype_to_name(ival & S_IFMT);
	if (name != NULL)
		strcpy(buf, name);
	else {
		unsigned first_ifmt_bit;

		// The lowest-valued "1" bit in S_IFMT
		first_ifmt_bit = S_IFMT & ~(S_IFMT - 1);
		sprintf(buf, "%03o", (ival & S_IFMT) / first_ifmt_bit);
	}

        // check on special bits
        if (S_ISUID & ival)
                strcat(buf, ",suid");
        if (S_ISGID & ival)
                strcat(buf, ",sgid");
        if (S_ISVTX & ival)
                strcat(buf, ",sticky");

	// and the read, write, execute flags in octal
	if (asprintf(&out, "%s,%03o", buf,
		     (S_IRWXU|S_IRWXG|S_IRWXO) & ival) < 0)
		out = NULL;
	return out;
}

static const char *print_mode_short_int(unsigned int ival)
{
	char *out, buf[48];

        // check on special bits
        buf[0] = 0;
        if (S_ISUID & ival)
                strcat(buf, "suid");
        if (S_ISGID & ival) {
                if (buf[0])
			strcat(buf, ",");
		strcat(buf, "sgid");
	}
        if (S_ISVTX & ival) {
                if (buf[0])
			strcat(buf, ",");
                strcat(buf, "sticky");
	}

	// and the read, write, execute flags in octal
	if (buf[0] == 0) {
		if (asprintf(&out, "0%03o",
			     (S_IRWXU|S_IRWXG|S_IRWXO) & ival) < 0)
			out = NULL;
	} else
		if (asprintf(&out, "%s,0%03o", buf,
			     (S_IRWXU|S_IRWXG|S_IRWXO) & ival) < 0)
			out = NULL;
	return out;
}

static const char *print_mode_short(const char *val, int base)
{
        unsigned int ival;
	char *out;

        errno = 0;
        ival = strtoul(val, NULL, base);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }
	return print_mode_short_int(ival);
}

static const char *print_socket_domain(const char *val)
{
	int i;
	char *out;
        const char *str;

	errno = 0;
        i = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
        str = fam_i2s(i);
        if (str == NULL) {
		if (asprintf(&out, "unknown-family(0x%s)", val) < 0)
			out = NULL;
		return out;
	} else
		return strdup(str);
}

static const char *print_socket_type(const char *val)
{
	unsigned int type;
	char *out;
        const char *str;

	errno = 0;
        type = 0xFF & strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
        str = sock_type_i2s(type);
        if (str == NULL) {
		if (asprintf(&out, "unknown-type(%s)", val) < 0)
			out = NULL;
		return out;
	} else
		return strdup(str);
}

static const char *print_socket_proto(const char *val)
{
	unsigned int proto;
	char *out;
        struct protoent *p;

	errno = 0;
        proto = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
        p = getprotobynumber(proto);
        if (p == NULL) {
		if (asprintf(&out, "unknown-proto(%s)", val) < 0)
			out = NULL;
		return out;
	} else
		return strdup(p->p_name);
}

static const char *print_sockaddr(const char *val)
{
        size_t slen;
        int rc = 0;
        const struct sockaddr *saddr;
        char name[NI_MAXHOST], serv[NI_MAXSERV];
        const char *host;
        char *out = NULL;
        const char *str;

        slen = strlen(val)/2;
        host = au_unescape((char *)val);
	if (host == NULL) {
		if (asprintf(&out, "malformed-host(%s)", val) < 0)
			out = NULL;
		return out;
	}
        saddr = (struct sockaddr *)host;


        str = fam_i2s(saddr->sa_family);
        if (str == NULL) {
		if (asprintf(&out, "unknown-family(%d)", saddr->sa_family) < 0)
			out = NULL;
		free((char *)host);
		return out;
	}

	// Now print address for some families
        switch (saddr->sa_family) {
                case AF_LOCAL:
                        {
                                const struct sockaddr_un *un =
                                        (struct sockaddr_un *)saddr;
                                if (un->sun_path[0])
					rc = asprintf(&out,
						"{ fam=%s path=%s }", str,
						      un->sun_path);
                                else // abstract name
					rc = asprintf(&out,
						"{ fam=%s path=%.108s }",
							str, &un->sun_path[1]);
                        }
                        break;
                case AF_INET:
                        if (slen < sizeof(struct sockaddr_in)) {
				rc = asprintf(&out,
					    "{ fam=%s sockaddr len too short }",
					     str);
				break;
                        }
                        slen = sizeof(struct sockaddr_in);
                        if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
                                NI_MAXSERV, NI_NUMERICHOST |
                                        NI_NUMERICSERV) == 0 ) {
				rc = asprintf(&out,
					      "{ fam=%s laddr=%s lport=%s }",
					      str, name, serv);
                        } else
				rc = asprintf(&out,
					    "{ fam=%s (error resolving addr) }",
					    str);
                        break;
                case AF_AX25:
                        {
                                const struct sockaddr_ax25 *x =
                                                (struct sockaddr_ax25 *)saddr;
				rc = asprintf(&out,
					      "{ fam=%s call=%c%c%c%c%c%c%c }",
					      str,
					      x->sax25_call.ax25_call[0],
					      x->sax25_call.ax25_call[1],
					      x->sax25_call.ax25_call[2],
					      x->sax25_call.ax25_call[3],
					      x->sax25_call.ax25_call[4],
					      x->sax25_call.ax25_call[5],
					      x->sax25_call.ax25_call[6]);
                        }
                        break;
                case AF_IPX:
                        {
                                const struct sockaddr_ipx *ip =
                                                (struct sockaddr_ipx *)saddr;
				rc = asprintf(&out,
					"{ fam=%s lport=%d ipx-net=%u }",
					str, ip->sipx_port, ip->sipx_network);
                        }
                        break;
                case AF_ATMPVC:
                        {
                                const struct sockaddr_atmpvc* at =
                                        (struct sockaddr_atmpvc *)saddr;
				rc = asprintf(&out, "{ fam=%s int=%d }", str,
					      at->sap_addr.itf);
                        }
                        break;
                case AF_X25:
                        {
                                const struct sockaddr_x25* x =
                                        (struct sockaddr_x25 *)saddr;
				rc = asprintf(&out, "{ fam=%s laddr=%.15s }",
					      str, x->sx25_addr.x25_addr);
                        }
                        break;
                case AF_INET6:
                        if (slen < sizeof(struct sockaddr_in6)) {
				rc = asprintf(&out,
					   "{ fam=%s sockaddr6 len too short }",
					   str);
				break;
                        }
                        slen = sizeof(struct sockaddr_in6);
                        if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
                                NI_MAXSERV, NI_NUMERICHOST |
                                        NI_NUMERICSERV) == 0 ) {
				rc = asprintf(&out,
						"{ fam=%s laddr=%s lport=%s }",
						str, name, serv);
                        } else
				rc = asprintf(&out,
					    "{ fam=%s (error resolving addr) }",
					    str);
                        break;
                case AF_NETLINK:
                        {
                                const struct sockaddr_nl *n =
                                                (struct sockaddr_nl *)saddr;
				rc = asprintf(&out,
					  "{ fam=%s nlnk-fam=%u nlnk-pid=%u }",
					  str, n->nl_family, n->nl_pid);
                        }
                        break;
		default:
			rc = asprintf(&out, "{ fam=%s (unsupported) }", str);
			break;
        }
	if (rc < 0)
		out = NULL;
        free((char *)host);
	return out;
}

/* This is only used in the RHEL4 kernel */
static const char *print_flags(const char *val)
{
        int flags, cnt = 0;
	size_t i;
	char *out, buf[80];

        errno = 0;
        flags = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }
        if (flags == 0) {
		if (asprintf(&out, "none") < 0)
			out = NULL;
                return out;
        }
	buf[0] = 0;
        for (i=0; i<FLAG_NUM_ENTRIES; i++) {
                if (flag_table[i].value & flags) {
                        if (!cnt) {
                                strcat(buf,
				       flag_strings + flag_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, ",");
                                strcat(buf,
				       flag_strings + flag_table[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%s", val);
	return strdup(buf);
}

static const char *print_promiscuous(const char *val)
{
        int ival;

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

        if (ival == 0)
                return strdup("no");
        else
                return strdup("yes");
}

static const char *print_capabilities(const char *val, int base)
{
        int cap;
	char *out;
	const char *s;

        errno = 0;
        cap = strtoul(val, NULL, base);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	s = cap_i2s(cap);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-capability(%s%s)",
				base == 16 ? "0x" : "", val) < 0)
		out = NULL;
	return out;
}

static const char *print_cap_bitmap(const char *val)
{
#define MASK(x) (1U << (x))
	unsigned long long temp;
	__u32 caps[2];
	int i, found=0;
	char *p, buf[600]; // 17 per cap * 33

	errno = 0;
	temp = strtoull(val, NULL, 16);
	if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
	}

        caps[0] =  temp & 0x00000000FFFFFFFFLL;
        caps[1] = (temp & 0xFFFFFFFF00000000LL) >> 32;
	p = buf;
	for (i=0; i <= CAP_LAST_CAP; i++) {
		if (MASK(i%32) & caps[i/32]) {
			const char *s;
			if (found)
				p = stpcpy(p, ",");
			s = cap_i2s(i);
			if (s != NULL)
				p = stpcpy(p, s);
			found = 1;
		}
	}
	if (found == 0)
		return strdup("none");
	return strdup(buf);
}

static const char *print_success(const char *val)
{
        int res;

	if (isdigit(*val)) {
	        errno = 0;
        	res = strtoul(val, NULL, 10);
	        if (errno) {
			char *out;
			if (asprintf(&out, "conversion error(%s)", val) < 0)
				out = NULL;
	                return out;
        	}

	        return strdup(aulookup_success(res));
	} else
		return strdup(val);
}

static const char *print_open_flags(const char *val)
{
	size_t i;
	unsigned int flags;
	int cnt = 0;
	char *out, buf[sizeof(open_flag_strings)+8];

	errno = 0;
	flags = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
               	return out;
       	}

	buf[0] = 0;
        if ((flags & O_ACCMODE) == 0) {
		// Handle O_RDONLY specially
                strcat(buf, "O_RDONLY");
                cnt++;
        }
        for (i=0; i<OPEN_FLAG_NUM_ENTRIES; i++) {
                if (open_flag_table[i].value & flags) {
                        if (!cnt) {
                                strcat(buf,
				open_flag_strings + open_flag_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				open_flag_strings + open_flag_table[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%s", val);
	return strdup(buf);
}

static const char *print_clone_flags(const char *val)
{
	unsigned int flags, i, clone_sig;
	int cnt = 0;
	char *out, buf[sizeof(clone_flag_strings)+16];// + 10 for signal name

	errno = 0;
	flags = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
               	return out;
       	}

	buf[0] = 0;
        for (i=0; i<CLONE_FLAG_NUM_ENTRIES; i++) {
                if (clone_flag_table[i].value & flags) {
                        if (!cnt) {
                                strcat(buf,
			clone_flag_strings + clone_flag_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
			clone_flag_strings + clone_flag_table[i].offset);
			}
                }
        }
	clone_sig = flags & 0xFF;
	if (clone_sig && (clone_sig < 32)) {
		const char *s = signal_i2s(clone_sig);
		if (s != NULL) {
			if (buf[0] != 0) 
				strcat(buf, "|");
			strcat(buf, s);
		}
	}

	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%x", flags);
	return strdup(buf);
}

static const char *print_fcntl_cmd(const char *val)
{
	char *out;
	const char *s;
	int cmd;

	errno = 0;
	cmd = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
       	}

	s = fcntl_i2s(cmd);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-fcntl-command(%d)", cmd) < 0)
		out = NULL;
	return out;
}

static const char *print_epoll_ctl(const char *val)
{
	char *out;
	const char *s;
	int cmd;

	errno = 0;
	cmd = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}

	s = epoll_ctl_i2s(cmd);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-epoll_ctl-operation(%d)", cmd) < 0)
		out = NULL;
	return out;
}

static const char *print_clock_id(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	else if (i < 7) {
		const char *s = clock_i2s(i);
		if (s != NULL)
			return strdup(s);
	}
	if (asprintf(&out, "unknown-clk_id(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_prot(const char *val, unsigned int is_mmap)
{
	unsigned int prot, i, limit;
	int cnt = 0;
	char buf[144];
	char *out;

	errno = 0;
        prot = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	buf[0] = 0;
        if ((prot & 0x07) == 0) {
		// Handle PROT_NONE specially
                strcat(buf, "PROT_NONE");
		return strdup(buf);
        }
	if (is_mmap)
		limit = 4;
	else
		limit = 3;
        for (i=0; i < limit; i++) {
                if (prot_table[i].value & prot) {
                        if (!cnt) {
                                strcat(buf,
				prot_strings + prot_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				prot_strings + prot_table[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%s", val);
	return strdup(buf);
}

static const char *print_mmap(const char *val)
{
	unsigned int maps, i;
	int cnt = 0;
	char buf[sizeof(mmap_strings)+8];
	char *out;

	errno = 0;
        maps = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	buf[0] = 0;
        if ((maps & 0x0F) == 0) {
		// Handle MAP_FILE specially
                strcat(buf, "MAP_FILE");
		cnt++;
        }
        for (i=0; i<MMAP_NUM_ENTRIES; i++) {
                if (mmap_table[i].value & maps) {
                        if (!cnt) {
                                strcat(buf,
				mmap_strings + mmap_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				mmap_strings + mmap_table[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%s", val);
	return strdup(buf);
}

static const char *print_personality(const char *val)
{
        int pers, pers2;
	char *out;
	const char *s;

        errno = 0;
        pers = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	pers2 = pers & ~ADDR_NO_RANDOMIZE;
	s = person_i2s(pers2);
	if (s != NULL) {
		if (pers & ADDR_NO_RANDOMIZE) {
			if (asprintf(&out, "%s|~ADDR_NO_RANDOMIZE", s) < 0)
				out = NULL;
			return out;
		} else
			return strdup(s);
	}
	if (asprintf(&out, "unknown-personality(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_ptrace(const char *val)
{
        int trace;
	char *out;
	const char *s;

        errno = 0;
        trace = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	s = ptrace_i2s(trace);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-ptrace(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_prctl_opt(const char *val)
{
        int opt;
	char *out;
	const char *s;

        errno = 0;
        opt = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	s = prctl_opt_i2s(opt);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-prctl-option(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_mount(const char *val)
{
	unsigned int mounts, i;
	int cnt = 0;
	char buf[334];
	char *out;

	errno = 0;
        mounts = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	buf[0] = 0;
        for (i=0; i<MOUNT_NUM_ENTRIES; i++) {
                if (mount_table[i].value & mounts) {
                        if (!cnt) {
                                strcat(buf,
				mount_strings + mount_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				mount_strings + mount_table[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%s", val);
	return strdup(buf);
}

static const char *print_rlimit(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	else if (i < 17) {
		const char *s = rlimit_i2s(i);
		if (s != NULL)
			return strdup(s);
	}
	if (asprintf(&out, "unknown-rlimit(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_recv(const char *val)
{
	unsigned int rec, i;
	int cnt = 0;
	char buf[sizeof(recv_strings)+8];
	char *out;

	errno = 0;
        rec = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	buf[0] = 0;
        for (i=0; i<RECV_NUM_ENTRIES; i++) {
                if (recv_table[i].value & rec) {
                        if (!cnt) {
                                strcat(buf,
				recv_strings + recv_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				recv_strings + recv_table[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%s", val);
	return strdup(buf);
}

static const char *print_access(const char *val)
{
	unsigned long mode;
	char buf[16];
	unsigned int i, cnt = 0;

	errno = 0;
        mode = strtoul(val, NULL, 16);
	if (errno) {
		char *out;
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}

	if ((mode & 0xF) == 0)
		return strdup("F_OK");
	buf[0] = 0;
	for (i=0; i<3; i++) {
		if (access_table[i].value & mode) {
			if (!cnt) {
				strcat(buf,
				access_strings + access_table[i].offset);
				cnt++;
			} else {
				strcat(buf, "|");
				strcat(buf,
				access_strings + access_table[i].offset);
			}
		}
	}
        if (buf[0] == 0)
                snprintf(buf, sizeof(buf), "0x%s", val);
        return strdup(buf);
}

static char *print_dirfd(const char *val)
{
	char *out;

	if (strcmp(val, "-100") == 0) {
		if (asprintf(&out, "AT_FDCWD") < 0)
			out = NULL;
	} else {
		if (asprintf(&out, "0x%s", val) < 0)
			out = NULL;
	}
	return out;
}

#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif
static const char *print_sched(const char *val)
{
        unsigned int pol;
        char *out;
        const char *s;

        errno = 0;
        pol = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	s = sched_i2s(pol & 0x0F);
	if (s != NULL) {
		char buf[48];

		strcpy(buf, s);
		if (pol & SCHED_RESET_ON_FORK )
			strcat(buf, "|SCHED_RESET_ON_FORK");
		return strdup(buf);
	}
	if (asprintf(&out, "unknown-scheduler-policy(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_sock_opt_level(const char *val)
{
        int lvl;
	char *out;

	errno = 0;
	lvl = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	if (lvl == SOL_SOCKET)
		return strdup("SOL_SOCKET");
	else {
		struct protoent *p = getprotobynumber(lvl);
		if (p == NULL) {
			const char *s = socklevel_i2s(lvl);
			if (s != NULL)
				return strdup(s);
			if (asprintf(&out, "unknown-sockopt-level(0x%s)", val) < 0)
				out = NULL;
		} else
			return strdup(p->p_name);
	}

	return out;
}

static const char *print_sock_opt_name(const char *val, int machine)
{
        int opt;
	char *out;
	const char *s;

        errno = 0;
        opt = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }
	// PPC's tables are different
	if ((machine == MACH_PPC64 || machine == MACH_PPC) &&
			opt >= 16 && opt <= 21)
		opt+=100;

	s = sockoptname_i2s(opt);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-sockopt-name(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_ip_opt_name(const char *val)
{
	int opt;
	char *out;
	const char *s;

	errno = 0;
	opt = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
	}

	s = ipoptname_i2s(opt);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-ipopt-name(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_ip6_opt_name(const char *val)
{
	int opt;
	char *out;
	const char *s;

	errno = 0;
	opt = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
	}

	s = ip6optname_i2s(opt);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-ip6opt-name(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_tcp_opt_name(const char *val)
{
	int opt;
	char *out;
	const char *s;

	errno = 0;
	opt = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
	}

	s = tcpoptname_i2s(opt);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-tcpopt-name(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_udp_opt_name(const char *val)
{
	int opt;
	char *out;

	errno = 0;
	opt = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
	}

	if (opt == 1)
		out = strdup("UDP_CORK");
	else if (opt == 100)
		out = strdup("UDP_ENCAP");
	else if (asprintf(&out, "unknown-udpopt-name(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_pkt_opt_name(const char *val)
{
	int opt;
	char *out;
	const char *s;

	errno = 0;
	opt = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
	}

	s = pktoptname_i2s(opt);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-pktopt-name(0x%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_shmflags(const char *val)
{
	unsigned int flags, partial, i;
	int cnt = 0;
	char *out, buf[sizeof(shm_mode_strings)+sizeof(ipccmd_strings)+8];

	errno = 0;
	flags = strtoul(val, NULL, 16);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
               	return out;
       	}

	partial = flags & 00003000;
	buf[0] = 0;
        for (i=0; i<IPCCMD_NUM_ENTRIES; i++) {
                if (ipccmd_table[i].value & partial) {
                        if (!cnt) {
                                strcat(buf,
			ipccmd_strings + ipccmd_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
			ipccmd_strings + ipccmd_table[i].offset);
			}
                }
        }

	partial = flags & 00014000;
        for (i=0; i<SHM_MODE_NUM_ENTRIES; i++) {
                if (shm_mode_table[i].value & partial) {
                        if (!cnt) {
                                strcat(buf,
			shm_mode_strings + shm_mode_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
			shm_mode_strings + shm_mode_table[i].offset);
			}
                }
        }

	partial = flags & 000777;
	const char *tmode = print_mode_short_int(partial);
	if (tmode) {
		if (buf[0] != 0)
			strcat(buf, "|");
		strcat(buf, tmode);
		free((void *)tmode);
	}

	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%x", flags);
	return strdup(buf);
}

static const char *print_seek(const char *val)
{
	unsigned int whence;
	char *out;
	const char *str;

	errno = 0;
	whence = 0xFF & strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	str = seek_i2s(whence);
	if (str == NULL) {
		if (asprintf(&out, "unknown-whence(%s)", val) < 0)
			out = NULL;
		return out;
	} else
		return strdup(str);
}

static const char *print_umount(const char *val)
{
	unsigned int flags, i;
	int cnt = 0;
	char buf[sizeof(umount_strings)+8];
	char *out;

	errno = 0;
	flags = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	buf[0] = 0;
	for (i=0; i<UMOUNT_NUM_ENTRIES; i++) {
                if (umount_table[i].value & flags) {
                        if (!cnt) {
				strcat(buf,
				umount_strings + umount_table[i].offset);
				cnt++;
                        } else {
				strcat(buf, "|");
				strcat(buf,
				umount_strings + umount_table[i].offset);
			}
                }
	}
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "0x%s", val);
	return strdup(buf);
}

static const char *print_ioctl_req(const char *val)
{
	int req;
	char *out;
	const char *r;

	errno = 0;
	req = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
	}

	r = ioctlreq_i2s(req);
	if (r != NULL)
		return strdup(r);
	if (asprintf(&out, "0x%x", req) < 0)
		out = NULL;
	return out;
}

static const char *fanotify[3]= { "unknown", "allow", "deny" };
static const char *aulookup_fanotify(unsigned s)
{
	switch (s)
	{
		default:
			return fanotify[0];
			break;
		case FAN_ALLOW:
			return fanotify[1];
			break;
		case FAN_DENY:
			return fanotify[2];
			break;
	}
}

static const char *print_fanotify(const char *val)
{
        int res;

	if (isdigit(*val)) {
	        errno = 0;
        	res = strtoul(val, NULL, 10);
	        if (errno) {
			char *out;
			if (asprintf(&out, "conversion error(%s)", val) < 0)
				out = NULL;
	                return out;
        	}

	        return strdup(aulookup_fanotify(res));
	} else
		return strdup(val);
}

static const char *print_exit_syscall(const char *val)
{
	char *out;

	if (strcmp(val, "0") == 0)
		out = strdup("EXIT_SUCCESS");
	else if (strcmp(val, "1") == 0)
		out = strdup("EXIT_FAILURE");
	else
		out = strdup("UNKNOWN");
	return out;
}

static const char *print_a0(const char *val, const idata *id)
{
	char *out;
	int machine = id->machine, syscall = id->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (*sys == 'r') {
			if (strcmp(sys, "rt_sigaction") == 0)
        	                return print_signals(val, 16);
			else if (strcmp(sys, "renameat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "readlinkat") == 0)
				return print_dirfd(val);
		} else if (*sys == 'c') {
			if (strcmp(sys, "clone") == 0)
				return print_clone_flags(val);
	                else if (strcmp(sys, "clock_settime") == 0)
				return print_clock_id(val);
		} else if (*sys == 'p') {
	                if (strcmp(sys, "personality") == 0)
				return print_personality(val);
                	else if (strcmp(sys, "ptrace") == 0)
				return print_ptrace(val);
			else if (strcmp(sys, "prctl") == 0)
				return print_prctl_opt(val);
		} else if (*sys == 'm') {
			if (strcmp(sys, "mkdirat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "mknodat") == 0)
				return print_dirfd(val);
		} else if (*sys == 'f') {
			if (strcmp(sys, "fchownat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "futimesat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "fchmodat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "faccessat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "futimensat") == 0)
				return print_dirfd(val);
		} else if (*sys == 'u') {
			if (strcmp(sys, "unshare") == 0)
				return print_clone_flags(val);
			else if (strcmp(sys, "unlinkat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "utimensat") == 0)
				return print_dirfd(val);
		} else if (strcmp(sys+1, "etrlimit") == 0)
			return print_rlimit(val);
		else if (*sys == 's') {
                	if (strcmp(sys, "setuid") == 0)
				return print_uid(val, 16);
        	        else if (strcmp(sys, "setreuid") == 0)
				return print_uid(val, 16);
	                else if (strcmp(sys, "setresuid") == 0)
				return print_uid(val, 16);
                	else if (strcmp(sys, "setfsuid") == 0)
				return print_uid(val, 16);
	                else if (strcmp(sys, "setgid") == 0)
				return print_gid(val, 16);
                	else if (strcmp(sys, "setregid") == 0)
				return print_gid(val, 16);
	                else if (strcmp(sys, "setresgid") == 0)
				return print_gid(val, 16);
                	else if (strcmp(sys, "socket") == 0)
				return print_socket_domain(val);
                	else if (strcmp(sys, "setfsgid") == 0)
				return print_gid(val, 16);
                	else if (strcmp(sys, "socketcall") == 0)
				return print_socketcall(val, 16);
		}
		else if (strcmp(sys, "linkat") == 0)
			return print_dirfd(val);
		else if (strcmp(sys, "newfstatat") == 0)
			return print_dirfd(val);
		else if (strcmp(sys, "openat") == 0)
			return print_dirfd(val);
               	else if (strcmp(sys, "ipccall") == 0)
			return print_ipccall(val, 16);
		else if (strncmp(sys, "exit", 4) == 0)
			return print_exit_syscall(val);
	}
	if (asprintf(&out, "0x%s", val) < 0)
			out = NULL;
	return out;
}

static const char *print_a1(const char *val, const idata *id)
{
	char *out;
	int machine = id->machine, syscall = id->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (*sys == 'f') {
			if (strcmp(sys, "fchmod") == 0)
				return print_mode_short(val, 16);
			else if (strncmp(sys, "fcntl", 5) == 0)
				return print_fcntl_cmd(val);
		} else if (*sys == 'c') {
			if (strcmp(sys, "chmod") == 0)
				return print_mode_short(val, 16);
			else if (strstr(sys, "chown"))
				return print_uid(val, 16);
			else if (strcmp(sys, "creat") == 0)
				return print_mode_short(val, 16);
		}
		if (strcmp(sys+1, "etsockopt") == 0)
			return print_sock_opt_level(val);
		else if (*sys == 's') {
	                if (strcmp(sys, "setreuid") == 0)
				return print_uid(val, 16);
                	else if (strcmp(sys, "setresuid") == 0)
				return print_uid(val, 16);
	                else if (strcmp(sys, "setregid") == 0)
				return print_gid(val, 16);
                	else if (strcmp(sys, "setresgid") == 0)
				return print_gid(val, 16);
	                else if (strcmp(sys, "socket") == 0)
				return print_socket_type(val);
			else if (strcmp(sys, "setns") == 0)
				return print_clone_flags(val);
			else if (strcmp(sys, "sched_setscheduler") == 0)
				return print_sched(val);
		} else if (*sys == 'm') {
			if (strcmp(sys, "mkdir") == 0)
				return print_mode_short(val, 16);
			else if (strcmp(sys, "mknod") == 0)
				return print_mode(val, 16);
			else if (strcmp(sys, "mq_open") == 0)
				return print_open_flags(val);
		}
		else if (strcmp(sys, "open") == 0)
			return print_open_flags(val);
		else if (strcmp(sys, "access") == 0)
			return print_access(val);
		else if (strcmp(sys, "epoll_ctl") == 0)
			return print_epoll_ctl(val);
		else if (strcmp(sys, "kill") == 0)
			return print_signals(val, 16);
		else if (strcmp(sys, "prctl") == 0) {
			if (id->a0 == PR_CAPBSET_READ ||
				id->a0 == PR_CAPBSET_DROP)
				return print_capabilities(val, 16);
			else if (id->a0 == PR_SET_PDEATHSIG)
				return print_signals(val, 16);
		}
		else if (strcmp(sys, "tkill") == 0)
			return print_signals(val, 16);
		else if (strcmp(sys, "umount2") == 0)
			return print_umount(val);
		else if (strcmp(sys, "ioctl") == 0)
			return print_ioctl_req(val);
	}
	if (asprintf(&out, "0x%s", val) < 0)
			out = NULL;
	return out;
}

static const char *print_a2(const char *val, const idata *id)
{
	char *out;
	int machine = id->machine, syscall = id->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (strncmp(sys, "fcntl", 5) == 0) {
			int ival;

			errno = 0;
			ival = strtoul(val, NULL, 16);
		        if (errno) {
				if (asprintf(&out, "conversion error(%s)",
					     val) < 0)
					out = NULL;
	                	return out;
	        	}
			switch (id->a1)
			{
				case F_SETOWN:
					return print_uid(val, 16);
				case F_SETFD:
					if (ival == FD_CLOEXEC)
						return strdup("FD_CLOEXEC");
					/* Fall thru okay. */
				case F_SETFL:
				case F_SETLEASE:
				case F_GETLEASE:
				case F_NOTIFY:
					break;
			}
		} else if (strcmp(sys+1, "etsockopt") == 0) {
			if (id->a1 == IPPROTO_IP)
				return print_ip_opt_name(val);
			else if (id->a1 == SOL_SOCKET)
				return print_sock_opt_name(val, machine);
			else if (id->a1 == IPPROTO_TCP)
				return print_tcp_opt_name(val);
			else if (id->a1 == IPPROTO_UDP)
				return print_udp_opt_name(val);
			else if (id->a1 == IPPROTO_IPV6)
				return print_ip6_opt_name(val);
			else if (id->a1 == SOL_PACKET)
				return print_pkt_opt_name(val);
			else
				goto normal;
		} else if (*sys == 'o') {
			if (strcmp(sys, "openat") == 0)
				return print_open_flags(val);
			if ((strcmp(sys, "open") == 0) && (id->a1 & O_CREAT))
				return print_mode_short(val, 16);
		} else if (*sys == 'f') {
			if (strcmp(sys, "fchmodat") == 0)
				return print_mode_short(val, 16);
			else if (strcmp(sys, "faccessat") == 0)
				return print_access(val);
		} else if (*sys == 's') {
                	if (strcmp(sys, "setresuid") == 0)
				return print_uid(val, 16);
	                else if (strcmp(sys, "setresgid") == 0)
				return print_gid(val, 16);
                	else if (strcmp(sys, "socket") == 0)
				return print_socket_proto(val);
	                else if (strcmp(sys, "sendmsg") == 0)
				return print_recv(val);
			else if (strcmp(sys, "shmget") == 0)
				return print_shmflags(val);
		} else if (*sys == 'm') {
			if (strcmp(sys, "mmap") == 0)
				return print_prot(val, 1);
			else if (strcmp(sys, "mkdirat") == 0)
				return print_mode_short(val, 16);
			else if (strcmp(sys, "mknodat") == 0)
				return print_mode_short(val, 16);
			else if (strcmp(sys, "mprotect") == 0)
				return print_prot(val, 0);
			else if ((strcmp(sys, "mq_open") == 0) &&
						(id->a1 & O_CREAT))
				return print_mode_short(val, 16);
		} else if (*sys == 'r') {
                	if (strcmp(sys, "recvmsg") == 0)
				return print_recv(val);
			else if (strcmp(sys, "readlinkat") == 0)
				return print_dirfd(val);
		} else if (*sys == 'l') {
			if (strcmp(sys, "linkat") == 0)
				return print_dirfd(val);
			else if (strcmp(sys, "lseek") == 0)
				return print_seek(val);
		}
		else if (strstr(sys, "chown"))
			return print_gid(val, 16);
		else if (strcmp(sys, "tgkill") == 0)
			return print_signals(val, 16);
	}
normal:
	if (asprintf(&out, "0x%s", val) < 0)
			out = NULL;
	return out;
}

static const char *print_a3(const char *val, const idata *id)
{
	char *out;
	int machine = id->machine, syscall = id->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (*sys == 'm') {
			if (strcmp(sys, "mmap") == 0)
				return print_mmap(val);
			else if (strcmp(sys, "mount") == 0)
				return print_mount(val);
		} else if (*sys == 'r') {
			if (strcmp(sys, "recv") == 0)
				return print_recv(val);
			else if (strcmp(sys, "recvfrom") == 0)
				return print_recv(val);
			else if (strcmp(sys, "recvmmsg") == 0)
				return print_recv(val);
		} else if (*sys == 's') {
			if (strcmp(sys, "send") == 0)
				return print_recv(val);
			else if (strcmp(sys, "sendto") == 0)
				return print_recv(val);
			else if (strcmp(sys, "sendmmsg") == 0)
				return print_recv(val);
		}
	}
	if (asprintf(&out, "0x%s", val) < 0)
			out = NULL;
	return out;
}

static const char *print_signals(const char *val, unsigned int base)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, base);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	else if (i < 32) {
		const char *s = signal_i2s(i);
		if (s != NULL)
			return strdup(s);
	}
	if (asprintf(&out, "unknown-signal(%s%s)",
					base == 16 ? "0x" : "", val) < 0)
		out = NULL;
	return out;
}

static const char *print_nfproto(const char *val)
{
        int proto;
	char *out;
	const char *s;

        errno = 0;
        proto = strtoul(val, NULL, 10);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	s = nfproto_i2s(proto);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-netfilter-protocol(%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_icmptype(const char *val)
{
        int icmptype;
	char *out;
	const char *s;

        errno = 0;
        icmptype = strtoul(val, NULL, 10);
        if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
                return out;
        }

	s = icmptype_i2s(icmptype);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-icmp-type(%s)", val) < 0)
		out = NULL;
	return out;
}

static const char *print_protocol(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 10);
	if (errno) { 
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
	} else {
		struct protoent *p = getprotobynumber(i);
		if (p)
			out = strdup(p->p_name);
		else
			out = strdup("undefined protocol");
	}
	return out;
}

/* FIXME - this assumes inet hook. Could also be an arp hook */
static const char *print_hook(const char *val)
{
	int hook;
	char *out;
	const char *str;

	errno = 0;
	hook = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	str = inethook_i2s(hook);
	if (str == NULL) {
		if (asprintf(&out, "unknown-hook(%s)", val) < 0)
			out = NULL;
		return out;
	} else
		return strdup(str);
}

static const char *print_netaction(const char *val)
{
	int action;
	char *out;
	const char *str;

	errno = 0;
	action = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	str = netaction_i2s(action);
	if (str == NULL) {
		if (asprintf(&out, "unknown-action(%s)", val) < 0)
			out = NULL;
		return out;
	} else
		return strdup(str);
}

/* Ethernet packet types */
static const char *print_macproto(const char *val)
{
	int type;
	char *out;

	errno = 0;
	type = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	if (type == 0x0800)
		return strdup("IP");
	else if (type == 0x0806)
		return strdup("ARP");
	return strdup("UNKNOWN");
}

static const char *print_addr(const char *val)
{
	char *out = strdup(val);
	return out;
}

static const char *print_list(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 10);
	if (errno) { 
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
	} else {
		const char *o = audit_flag_to_name(i);
		if (o != NULL)
			out = strdup(o);
		else if (asprintf(&out, "unknown-list(%s)", val) < 0)
			out = NULL;
	}
	return out;
}

struct string_buf {
	char *buf; /* NULL if was ever out of memory */
	size_t allocated;
	size_t pos;
};

/* Append c to buf. */
static void append_char(struct string_buf *buf, char c)
{
	if (buf->buf == NULL)
		return;
	if (buf->pos == buf->allocated) {
		char *p;

		buf->allocated *= 2;
		p = realloc(buf->buf, buf->allocated);
		if (p == NULL) {
			free(buf->buf);
			buf->buf = NULL;
			return;
		}
		buf->buf = p;
	}
	buf->buf[buf->pos] = c;
	buf->pos++;
}

/* Represent c as a character within a quoted string, and append it to buf. */
static void tty_append_printable_char(struct string_buf *buf, unsigned char c)
{
	if (c < 0x20 || c > 0x7E) {
		append_char(buf, '\\');
		append_char(buf, '0' + ((c >> 6) & 07));
		append_char(buf, '0' + ((c >> 3) & 07));
		append_char(buf, '0' + (c & 07));
	} else {
		if (c == '\\' || c ==  '"')
			append_char(buf, '\\');
		append_char(buf, c);
	}
}

/* Search for a name of a sequence of TTY bytes.
   If found, return the name and advance *INPUT.  Return NULL otherwise. */
static const char *tty_find_named_key(unsigned char **input, size_t input_len)
{
	/* NUL-terminated list of (sequence, NUL, name, NUL) entries.
	   First match wins, even if a longer match were possible later */
	static const unsigned char named_keys[] =
#define E(SEQ, NAME) SEQ "\0" NAME "\0"
#include "tty_named_keys.h"
#undef E
		"\0";

	unsigned char *src;
	const unsigned char *nk;

	src = *input;
	if (*src >= ' ' && (*src < 0x7F || *src >= 0xA0))
		return NULL; /* Fast path */
	nk = named_keys;
	do {
		const unsigned char *p;
		size_t nk_len;

		p = strchr(nk, '\0');
		nk_len = p - nk;
		if (nk_len <= input_len && memcmp(src, nk, nk_len) == 0) {
			*input += nk_len;
			return p + 1;
		}
		nk = strchr(p + 1, '\0') + 1;
	} while (*nk != '\0');
	return NULL;
}

static const char *print_tty_data(const char *raw_data)
{
	struct string_buf buf;
	int in_printable;
	unsigned char *data, *data_pos, *data_end;

	if (!is_hex_string(raw_data))
		return strdup(raw_data);
	data = au_unescape((char *)raw_data);
	if (data == NULL)
		return NULL;
	data_end = data + strlen(raw_data) / 2;

	buf.allocated = 10;
	buf.buf = malloc(buf.allocated); /* NULL handled in append_char() */
	buf.pos = 0;
	in_printable = 0;
	data_pos = data;
	while (data_pos < data_end) {
		/* FIXME: Unicode */
		const char *desc;

		desc = tty_find_named_key(&data_pos, data_end - data_pos);
		if (desc != NULL) {
			if (in_printable != 0) {
				append_char(&buf, '"');
				in_printable = 0;
			}
			if (buf.pos != 0)
				append_char(&buf, ',');
			append_char(&buf, '<');
			while (*desc != '\0') {
				append_char(&buf, *desc);
				desc++;
			}
			append_char(&buf, '>');
		} else {
			if (in_printable == 0) {
				if (buf.pos != 0)
					append_char(&buf, ',');
				append_char(&buf, '"');
				in_printable = 1;
			}
			tty_append_printable_char(&buf, *data_pos);
			data_pos++;
		}
	}
	if (in_printable != 0)
		append_char(&buf, '"');
	append_char(&buf, '\0');
	free(data);
	return buf.buf;
}

static const char *print_session(const char *val)
{
	if (strcmp(val, "4294967295") == 0)
		return strdup("unset");
	else
		return strdup(val);
}

#define SECCOMP_RET_ACTION      0x7fff0000U
static const char *print_seccomp_code(const char *val)
{
	unsigned long code;
	char *out;
	const char *s;

	errno = 0;
        code = strtoul(val, NULL, 16);
	if (errno) {
		if (asprintf(&out, "conversion error(%s)", val) < 0)
			out = NULL;
		return out;
	}
	s = seccomp_i2s(code & SECCOMP_RET_ACTION);
	if (s != NULL)
		return strdup(s);
	if (asprintf(&out, "unknown-seccomp-code(%s)", val) < 0)
		out = NULL;
	return out;
}

int lookup_type(const char *name)
{
	int i;

	if (type_s2i(name, &i) != 0)
		return i;
	return AUPARSE_TYPE_UNCLASSIFIED;
}

/*
 * This is the main entry point for the auparse library. Call chain is:
 * auparse_interpret_field -> nvlist_interp_cur_val -> interpret
 */
const char *interpret(const rnode *r, auparse_esc_t escape_mode)
{
	const nvlist *nv = &r->nv;
	int type;
	idata id;
	nvnode *n;
	const char *out;

	id.machine = r->machine;
	id.syscall = r->syscall;
	id.a0 = r->a0;
	id.a1 = r->a1;
	id.cwd = r->cwd;
	id.name = nvlist_get_cur_name(nv);
	id.val = nvlist_get_cur_val(nv);
	type = auparse_interp_adjust_type(r->type, id.name, id.val);

	out = auparse_do_interpretation(type, &id, escape_mode);
	n = nvlist_get_cur(nv);
	n->interp_val = (char *)out;

	return out;
}

/* 
 * rtype:   the record type
 * name:    the current field name
 * value:   the current field value
 * Returns: field's internal type is returned
 */
int auparse_interp_adjust_type(int rtype, const char *name, const char *val)
{
	int type;

	/* This set of statements overrides or corrects the detection.
	 * In almost all cases its a double use of a field. */
	if (rtype == AUDIT_EXECVE && *name == 'a' && strcmp(name, "argc") &&
			!strstr(name, "_len"))
		type = AUPARSE_TYPE_ESCAPED;
	else if (rtype == AUDIT_AVC && strcmp(name, "saddr") == 0)
		type = AUPARSE_TYPE_UNCLASSIFIED;
	else if (rtype == AUDIT_USER_TTY && strcmp(name, "msg") == 0)
		type = AUPARSE_TYPE_ESCAPED;
	else if (rtype == AUDIT_NETFILTER_PKT && strcmp(name, "saddr") == 0)
		type = AUPARSE_TYPE_ADDR;
	else if (strcmp(name, "acct") == 0) {
		if (val[0] == '"')
			type = AUPARSE_TYPE_ESCAPED;
		else if (is_hex_string(val))
			type = AUPARSE_TYPE_ESCAPED;
		else
			type = AUPARSE_TYPE_UNCLASSIFIED;
	} else if (rtype == AUDIT_PATH && *name =='f' &&
			strcmp(name, "flags") == 0)
		type = AUPARSE_TYPE_FLAGS;
	else if (rtype == AUDIT_MQ_OPEN && strcmp(name, "mode") == 0)
		type = AUPARSE_TYPE_MODE_SHORT;
	else if (rtype == AUDIT_CRYPTO_KEY_USER && strcmp(name, "fp") == 0)
		type = AUPARSE_TYPE_UNCLASSIFIED;
	else if ((strcmp(name, "id") == 0) &&
		(rtype == AUDIT_ADD_GROUP || rtype == AUDIT_GRP_MGMT ||
			rtype == AUDIT_DEL_GROUP))
		type = AUPARSE_TYPE_GID;
	else
		type = lookup_type(name);

	return type;
}

/*
 * This can be called by either interpret() or from ausearch-report or
 * auditctl-listing.c. Returns a malloc'ed buffer that the caller must free.
 */
char *auparse_do_interpretation(int type, const idata *id,
	auparse_esc_t escape_mode)
{
	const char *out;

	// Check the interpretations list first
	if (il.head) {
		nvlist_first(&il);
		if (nvlist_find_name(&il, id->name)) {
			const char *val = il.cur->interp_val;

			if (val) {
				// If we don't know what it is when auditd
				// recorded it, try it again incase the
				// libraries have been updated to support it.
				if (strncmp(val, "unknown-", 8 ) == 0)
					goto unknown; 
				if (type == AUPARSE_TYPE_UID ||
						type == AUPARSE_TYPE_GID)
					return print_escaped(val);
				else
					return strdup(val);
			}
		}
	}
unknown:

	switch(type) {
		case AUPARSE_TYPE_UID:
			out = print_uid(id->val, 10);
			break;
		case AUPARSE_TYPE_GID:
			out = print_gid(id->val, 10);
			break;
		case AUPARSE_TYPE_SYSCALL:
			out = print_syscall(id);
			break;
		case AUPARSE_TYPE_ARCH:
			out = print_arch(id->val, id->machine);
			break;
		case AUPARSE_TYPE_EXIT:
			out = print_exit(id->val);
			break;
		case AUPARSE_TYPE_ESCAPED:
		case AUPARSE_TYPE_ESCAPED_FILE:
			out = print_escaped_ext(id);
			break;
		case AUPARSE_TYPE_ESCAPED_KEY:
			out = print_escaped(id->val);
			break;
		case AUPARSE_TYPE_PERM:
			out = print_perm(id->val);
			break;
		case AUPARSE_TYPE_MODE:
			out = print_mode(id->val,8);
			break;
		case AUPARSE_TYPE_MODE_SHORT:
			out = print_mode_short(id->val,8);
			break;
		case AUPARSE_TYPE_SOCKADDR:
			out = print_sockaddr(id->val);
			break;
		case AUPARSE_TYPE_FLAGS:
			out = print_flags(id->val);
			break;
		case AUPARSE_TYPE_PROMISC:
			out = print_promiscuous(id->val);
			break;
		case AUPARSE_TYPE_CAPABILITY:
			out = print_capabilities(id->val, 10);
			break;
		case AUPARSE_TYPE_SUCCESS:
			out = print_success(id->val);
			break;
		case AUPARSE_TYPE_A0:
			out = print_a0(id->val, id);
			break;
		case AUPARSE_TYPE_A1:
			out = print_a1(id->val, id);
			break;
		case AUPARSE_TYPE_A2:
			out = print_a2(id->val, id);
			break; 
		case AUPARSE_TYPE_A3:
			out = print_a3(id->val, id);
			break; 
		case AUPARSE_TYPE_SIGNAL:
			out = print_signals(id->val, 10);
			break; 
		case AUPARSE_TYPE_LIST:
			out = print_list(id->val);
			break;
		case AUPARSE_TYPE_TTY_DATA:
			out = print_tty_data(id->val);
			break;
		case AUPARSE_TYPE_SESSION:
			out = print_session(id->val);
			break;
		case AUPARSE_TYPE_CAP_BITMAP:
			out = print_cap_bitmap(id->val);
			break;
		case AUPARSE_TYPE_NFPROTO:
			out = print_nfproto(id->val);
			break; 
		case AUPARSE_TYPE_ICMPTYPE:
			out = print_icmptype(id->val);
			break; 
		case AUPARSE_TYPE_PROTOCOL:
			out = print_protocol(id->val);
			break; 
		case AUPARSE_TYPE_ADDR:
			out = print_addr(id->val);
			break;
		case AUPARSE_TYPE_PERSONALITY:
			out = print_personality(id->val);
			break;
		case AUPARSE_TYPE_SECCOMP:
			out = print_seccomp_code(id->val);
			break;
		case AUPARSE_TYPE_OFLAG:
			out = print_open_flags(id->val);
			break;
		case AUPARSE_TYPE_MMAP:
			out = print_mmap(id->val);
			break;
		case AUPARSE_TYPE_PROCTITLE:
			out = print_proctitle(id->val);
			break;
		case AUPARSE_TYPE_HOOK:
			out = print_hook(id->val);
			break;
		case AUPARSE_TYPE_NETACTION:
			out = print_netaction(id->val);
			break;
		case AUPARSE_TYPE_MACPROTO:
			out = print_macproto(id->val);
			break;
		case AUPARSE_TYPE_IOCTL_REQ:
			out = print_ioctl_req(id->val);
			break;
		case AUPARSE_TYPE_FANOTIFY:
			out = print_fanotify(id->val);
			break;
		case AUPARSE_TYPE_MAC_LABEL:
		case AUPARSE_TYPE_UNCLASSIFIED:
		default:
			out = strdup(id->val);
			break;
        }

	if (escape_mode != AUPARSE_ESC_RAW && out) {
		char *str = NULL;
		unsigned int len = strlen(out);
		if (type == AUPARSE_TYPE_ESCAPED_KEY) {
			// The audit key separator causes a false
			// positive in deciding to escape.
			str = strchr(out, AUDIT_KEY_SEPARATOR);
		}
		if (str == NULL) {
			// This is the normal path
			unsigned int cnt = need_escaping(out, len, escape_mode);
			if (cnt) {
				char *dest = malloc(len + 1 + (3*cnt));
				if (dest)
					escape(out, dest, len, escape_mode);
				free((void *)out);
				out = dest;
			}
		} else {
			// We have multiple keys. Need to look at each one.
			unsigned int cnt = 0;
			char *ptr = out;

 			while (*ptr) {
				unsigned int klen = str - ptr;
				char tmp = *str;
				*str = 0;
				cnt += need_escaping(ptr, klen, escape_mode);
				*str = tmp;
				ptr = str;
				// If we are not at the end...
				if (tmp) {
					ptr++;
					str = strchr(ptr, AUDIT_KEY_SEPARATOR);
					// If we don't have anymore, just
					// point to the end
					if (str == NULL)
						str = strchr(ptr, 0);
				}
			}
			if (cnt) {
				// I expect this code to never get used.
				// Its here just in the off chance someone
				// actually put a control character in a key.
				char *dest = malloc(len + 1 + (3*cnt));
				if (dest)
					key_escape(out, dest, escape_mode);
				free((void *)out);
				out = dest;
			}
		}
	}
	return out;
}
